package dev.personalcloud.android.core;

import java.util.Map;

/** Small persistence boundary; Android implementation encrypts the serialized state with Android Keystore. */
public interface StateStore {
    Map<String, Object> load() throws Exception;
    void save(Map<String, Object> state) throws Exception;

    /** Independent encrypted persistence namespace; it cannot be overwritten by peer-protocol saves. */
    Map<String, Object> loadDomain(String domain) throws Exception;
    void saveDomain(String domain, Map<String, Object> state) throws Exception;
}
