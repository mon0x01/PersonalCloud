package dev.personalcloud.storage;

import dev.personalcloud.core.StateStore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Durable per-member daily filesystem budgets.
 *
 * <p>Each network member gets independent write-byte and delete-entry budgets
 * for the current UTC day. Writes reserve their declared size before streaming
 * and settle it immediately before publication; recursive deletes count every
 * entry before touching the tree. Reservations make concurrent operations
 * account for each other, and the ledger survives process restart in the same
 * StateStore used by the rest of the node.</p>
 *
 * <p>A limit of {@code 0} means unlimited. Per-member override records allow the
 * owner to raise or lower a single device without changing every member.</p>
 */
public final class FilesystemBudgetService {
    public static final long DEFAULT_DAILY_WRITE_BYTES = 20L * 1024 * 1024 * 1024;
    public static final long DEFAULT_DAILY_DELETE_ENTRIES = 10_000;
    public static final long MAX_DAILY_WRITE_BYTES = 1024L * 1024 * 1024 * 1024;
    public static final long MAX_DAILY_DELETE_ENTRIES = 1_000_000;

    private static final String USAGE_PREFIX = "filesystem.budget.usage";
    private static final String POLICY_PREFIX = "filesystem.budget.limit";
    private static final int RETENTION_DAYS = 2;

    private final StateStore state;
    private final long defaultWriteBytes;
    private final long defaultDeleteEntries;
    private final Supplier<LocalDate> clock;
    private String lastPrunedDay = "";

    public FilesystemBudgetService(StateStore state) {
        this(state, environmentLong("PERSONALCLOUD_MEMBER_DAILY_WRITE_BYTES",
                        DEFAULT_DAILY_WRITE_BYTES, MAX_DAILY_WRITE_BYTES),
                environmentLong("PERSONALCLOUD_MEMBER_DAILY_DELETE_ENTRIES",
                        DEFAULT_DAILY_DELETE_ENTRIES, MAX_DAILY_DELETE_ENTRIES),
                () -> LocalDate.now(ZoneOffset.UTC));
    }

    public FilesystemBudgetService(StateStore state, long defaultWriteBytes, long defaultDeleteEntries) {
        this(state, defaultWriteBytes, defaultDeleteEntries, () -> LocalDate.now(ZoneOffset.UTC));
    }

    FilesystemBudgetService(StateStore state, long defaultWriteBytes, long defaultDeleteEntries,
                            Supplier<LocalDate> clock) {
        if (state == null) throw new IllegalArgumentException("A state store is required for filesystem budgets.");
        this.state = state;
        this.defaultWriteBytes = validateWriteLimit(defaultWriteBytes);
        this.defaultDeleteEntries = validateDeleteLimit(defaultDeleteEntries);
        this.clock = clock == null ? () -> LocalDate.now(ZoneOffset.UTC) : clock;
    }

    /** Reserves write bytes for a member before an upload begins. */
    public synchronized Reservation reserveWrite(String memberId, long bytes) throws Exception {
        return reserve(memberId, bytes, true);
    }

    /** Converts a write reservation into durable usage. */
    public synchronized void commitWrite(Reservation reservation) throws Exception {
        settle(reservation, true, true);
    }

    /** Releases a write reservation when nothing was published. */
    public synchronized void releaseWrite(Reservation reservation) throws Exception {
        settle(reservation, true, false);
    }

    /** Reserves deleted entries before a destructive operation begins. */
    public synchronized Reservation reserveDelete(String memberId, long entries) throws Exception {
        return reserve(memberId, entries, false);
    }

    /** Converts a delete reservation into durable usage. Conservative on partial deletion. */
    public synchronized void commitDelete(Reservation reservation) throws Exception {
        settle(reservation, false, true);
    }

    public synchronized long writeLimit(String memberId) {
        String member = requireMember(memberId);
        Map<String, String> policy = state.getRecord(POLICY_PREFIX, key(member));
        return policy == null ? defaultWriteBytes : readNumber(policy, "writeBytesPerDay");
    }

    public synchronized long deleteLimit(String memberId) {
        String member = requireMember(memberId);
        Map<String, String> policy = state.getRecord(POLICY_PREFIX, key(member));
        return policy == null ? defaultDeleteEntries : readNumber(policy, "deleteEntriesPerDay");
    }

    /** Current-day usage and effective limits for one member. */
    public synchronized Map<String, Object> status(String memberId) {
        String member = requireMember(memberId);
        String day = clock.get().toString();
        prune(day);
        Map<String, String> usage = usage(member, day);
        long writeLimit = writeLimit(member);
        long deleteLimit = deleteLimit(member);
        long writeUsed = readNumber(usage, "writeBytes");
        long writeReserved = readNumber(usage, "reservedWriteBytes");
        long deleteUsed = readNumber(usage, "deleteEntries");
        long deleteReserved = readNumber(usage, "reservedDeleteEntries");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("memberId", member);
        result.put("day", day);
        result.put("writeBytesPerDay", writeLimit);
        result.put("writeBytesUsed", writeUsed);
        result.put("writeBytesReserved", writeReserved);
        result.put("writeBytesRemaining", remaining(writeLimit, writeUsed, writeReserved));
        result.put("deleteEntriesPerDay", deleteLimit);
        result.put("deleteEntriesUsed", deleteUsed);
        result.put("deleteEntriesReserved", deleteReserved);
        result.put("deleteEntriesRemaining", remaining(deleteLimit, deleteUsed, deleteReserved));
        result.put("unlimited", writeLimit == 0 && deleteLimit == 0);
        result.put("policyOverride", state.getRecord(POLICY_PREFIX, key(member)) != null);
        return result;
    }

    /** Current-day usage for every member with a ledger or an override. */
    public synchronized List<Map<String, Object>> statuses() {
        String day = clock.get().toString();
        prune(day);
        Map<String, String> members = new LinkedHashMap<>();
        for (Map<String, String> row : state.records(USAGE_PREFIX)) {
            if (day.equals(row.get("day"))) members.putIfAbsent(String.valueOf(row.get("memberId")), day);
        }
        for (Map<String, String> row : state.records(POLICY_PREFIX)) {
            String member = row.get("memberId");
            if (member != null && !member.isBlank()) members.putIfAbsent(member, day);
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (String member : members.keySet()) result.add(status(member));
        result.sort(Comparator.comparing(row -> String.valueOf(row.get("memberId"))));
        return List.copyOf(result);
    }

    /** Sets a per-member override. A zero limit disables that dimension. */
    public synchronized Map<String, Object> setPolicy(String memberId, long writeBytesPerDay,
                                                      long deleteEntriesPerDay) throws Exception {
        String member = requireMember(memberId);
        validateWriteLimit(writeBytesPerDay);
        validateDeleteLimit(deleteEntriesPerDay);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("memberId", member);
        fields.put("writeBytesPerDay", Long.toString(writeBytesPerDay));
        fields.put("deleteEntriesPerDay", Long.toString(deleteEntriesPerDay));
        fields.put("updated", Instant.now().toString());
        state.putRecord(POLICY_PREFIX, key(member), fields);
        return status(member);
    }

    /** Removes a member override and restores the node defaults. */
    public synchronized Map<String, Object> clearPolicy(String memberId) throws Exception {
        String member = requireMember(memberId);
        state.removeRecord(POLICY_PREFIX, key(member));
        return status(member);
    }

    private Reservation reserve(String memberId, long amount, boolean write) throws Exception {
        String member = requireMember(memberId);
        if (amount < 0) throw new IllegalArgumentException("A budget reservation cannot be negative.");
        String day = clock.get().toString();
        prune(day);
        if (amount == 0) return new Reservation(member, day, 0, write);
        Map<String, String> usage = usage(member, day);
        long limit = write ? writeLimit(member) : deleteLimit(member);
        long used = readNumber(usage, write ? "writeBytes" : "deleteEntries");
        long reserved = readNumber(usage, write ? "reservedWriteBytes" : "reservedDeleteEntries");
        long total;
        try {
            total = Math.addExact(Math.addExact(used, reserved), amount);
        } catch (ArithmeticException overflow) {
            throw new FilesystemBudgetExceededException(member, write ? "write-byte" : "delete-entry",
                    limit, used, reserved, amount, secondsUntilUtcMidnight(day));
        }
        if (limit > 0 && total > limit) {
            throw new FilesystemBudgetExceededException(member, write ? "write-byte" : "delete-entry",
                    limit, used, reserved, amount, secondsUntilUtcMidnight(day));
        }
        usage.put("memberId", member);
        usage.put("day", day);
        usage.put(write ? "reservedWriteBytes" : "reservedDeleteEntries", Long.toString(total - used));
        state.putRecord(USAGE_PREFIX, id(day, member), usage);
        return new Reservation(member, day, amount, write);
    }

    private void settle(Reservation reservation, boolean write, boolean commit) throws Exception {
        if (reservation == null || reservation.amount() == 0) return;
        if (reservation.write() != write) {
            throw new IllegalArgumentException("Budget reservation kind does not match its settlement.");
        }
        String member = reservation.memberId();
        String day = reservation.day();
        Map<String, String> usage = usage(member, day);
        long reserved = readNumber(usage, write ? "reservedWriteBytes" : "reservedDeleteEntries");
        if (reserved < reservation.amount()) {
            // A lost or pruned reservation cannot be released safely. A commit
            // still records the usage so the budget remains fail-closed.
            if (!commit) return;
            reserved = reservation.amount();
        }
        long nextReserved = reserved - reservation.amount();
        usage.put("memberId", member);
        usage.put("day", day);
        usage.put(write ? "reservedWriteBytes" : "reservedDeleteEntries", Long.toString(nextReserved));
        long used = readNumber(usage, write ? "writeBytes" : "deleteEntries");
        if (commit) {
            try {
                used = Math.addExact(used, reservation.amount());
            } catch (ArithmeticException overflow) {
                throw new FilesystemBudgetExceededException(member, write ? "write-byte" : "delete-entry",
                        0, used, nextReserved, reservation.amount(), secondsUntilUtcMidnight(day));
            }
            usage.put(write ? "writeBytes" : "deleteEntries", Long.toString(used));
        }
        if (used == 0 && nextReserved == 0) {
            state.removeRecord(USAGE_PREFIX, id(day, member));
        } else {
            state.putRecord(USAGE_PREFIX, id(day, member), usage);
        }
    }

    private Map<String, String> usage(String member, String day) {
        Map<String, String> existing = state.getRecord(USAGE_PREFIX, id(day, member));
        return existing == null ? new LinkedHashMap<>() : new LinkedHashMap<>(existing);
    }

    private void prune(String day) {
        if (day.equals(lastPrunedDay)) return;
        try {
            LocalDate cutoff = LocalDate.parse(day).minusDays(RETENTION_DAYS - 1L);
            for (Map<String, String> row : state.records(USAGE_PREFIX)) {
                String rowDay = row.get("day");
                String rowId = row.get("_id");
                if (rowId == null) continue;
                try {
                    if (rowDay == null || LocalDate.parse(rowDay).isBefore(cutoff)) {
                        state.removeRecord(USAGE_PREFIX, rowId);
                    }
                } catch (RuntimeException malformed) {
                    state.removeRecord(USAGE_PREFIX, rowId);
                }
            }
            lastPrunedDay = day;
        } catch (Exception cleanupFailure) {
            // Retention cleanup must not make a well-formed request fail.
            // The ledger remains bounded by member count and retained days.
        }
    }

    private static long remaining(long limit, long used, long reserved) {
        if (limit == 0) return -1;
        return Math.max(0, limit - Math.max(0, used) - Math.max(0, reserved));
    }

    private static String id(String day, String member) {
        return day + "-" + key(member);
    }

    private static String key(String member) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(member.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 16);
        } catch (Exception unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable for filesystem budget keys.", unavailable);
        }
    }

    private static long readNumber(Map<String, String> values, String key) {
        String raw = values.get(key);
        if (raw == null || raw.isBlank()) return 0;
        try {
            long value = Long.parseLong(raw);
            if (value < 0) throw new NumberFormatException("negative");
            return value;
        } catch (NumberFormatException malformed) {
            throw new IllegalStateException("Stored filesystem budget value '" + key + "' is invalid.");
        }
    }

    private static String requireMember(String memberId) {
        if (memberId == null || memberId.isBlank()) {
            throw new IllegalArgumentException("An authenticated member ID is required for filesystem budgets.");
        }
        return memberId;
    }

    private static long validateWriteLimit(long value) {
        if (value < 0 || value > MAX_DAILY_WRITE_BYTES) {
            throw new IllegalArgumentException("Daily write budget must be between 0 and 1 TiB.");
        }
        return value;
    }

    private static long validateDeleteLimit(long value) {
        if (value < 0 || value > MAX_DAILY_DELETE_ENTRIES) {
            throw new IllegalArgumentException("Daily delete budget must be between 0 and 1,000,000 entries.");
        }
        return value;
    }

    private static long environmentLong(String name, long fallback, long maximum) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) return fallback;
        try {
            long parsed = Long.parseLong(raw.trim());
            if (parsed < 0 || parsed > maximum) {
                throw new IllegalArgumentException(name + " must be between 0 and " + maximum + ".");
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(name + " must be a non-negative integer.", invalid);
        }
    }

    private static long secondsUntilUtcMidnight(String day) {
        try {
            Instant next = LocalDate.parse(day).plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
            return Math.max(1, Duration.between(Instant.now(), next).getSeconds());
        } catch (RuntimeException malformed) {
            return 60;
        }
    }

    /** A pending write-byte or delete-entry reservation. */
    public record Reservation(String memberId, String day, long amount, boolean write) { }
}
