/**
 * MailSentry AI — Forensic Evidence Storage & Persistent Vault (IndexedDB)
 * Ensures evidence blocks, forensic case archives, and BSA 2023 panchnamas
 * persist permanently in browser storage across reboots and page refreshes.
 */

window.ForensicStorage = {
  dbName: 'MailSentryVaultDB',
  dbVersion: 1,
  db: null,

  async init() {
    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
      if (!window.indexedDB) {
        console.warn('[MailSentry Storage] IndexedDB not available, falling back to session RAM.');
        resolve(null);
        return;
      }

      const request = indexedDB.open(this.dbName, this.dbVersion);

      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        // Blockchain Ledger Store
        if (!db.objectStoreNames.contains('ledger')) {
          const ledgerStore = db.createObjectStore('ledger', { keyPath: 'blockIndex' });
          ledgerStore.createIndex('blockHash', 'blockHash', { unique: true });
          ledgerStore.createIndex('timestamp', 'timestamp', { unique: false });
          ledgerStore.createIndex('originIp', 'originIp', { unique: false });
        }

        // Triage Cases Store
        if (!db.objectStoreNames.contains('cases')) {
          const casesStore = db.createObjectStore('cases', { keyPath: 'id' });
          casesStore.createIndex('date', 'date', { unique: false });
          casesStore.createIndex('threatTier', 'threatTier', { unique: false });
        }
      };

      request.onsuccess = (e) => {
        this.db = e.target.result;
        console.log('[MailSentry Storage] Persistent Forensic Vault (IndexedDB) Online.');
        resolve(this.db);
      };

      request.onerror = (e) => {
        console.error('[MailSentry Storage] Failed to open IndexedDB:', e);
        resolve(null);
      };
    });
  },

  /**
   * Save a sealed evidence block to IndexedDB
   * @param {Object} block 
   */
  async saveBlock(block) {
    await this.init();
    if (!this.db) return false;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction(['ledger'], 'readwrite');
        const store = tx.objectStore('ledger');
        store.put(block);
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => resolve(false);
      } catch (err) {
        console.error('[MailSentry Storage] Error saving block:', err);
        resolve(false);
      }
    });
  },

  /**
   * Load all sealed blocks from persistent storage
   */
  async getAllBlocks() {
    await this.init();
    if (!this.db) return [];

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction(['ledger'], 'readonly');
        const store = tx.objectStore('ledger');
        const request = store.getAll();
        request.onsuccess = () => {
          const blocks = request.result || [];
          blocks.sort((a, b) => a.blockIndex - b.blockIndex);
          resolve(blocks);
        };
        request.onerror = () => resolve([]);
      } catch (err) {
        console.error('[MailSentry Storage] Error getting blocks:', err);
        resolve([]);
      }
    });
  },

  /**
   * Save a complete forensic triage case
   * @param {Object} caseRecord 
   */
  async saveCase(caseRecord) {
    await this.init();
    if (!this.db) return false;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction(['cases'], 'readwrite');
        const store = tx.objectStore('cases');
        store.put(caseRecord);
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => resolve(false);
      } catch (err) {
        console.error('[MailSentry Storage] Error saving case:', err);
        resolve(false);
      }
    });
  },

  /**
   * Load all saved cases
   */
  async getAllCases() {
    await this.init();
    if (!this.db) return [];

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction(['cases'], 'readonly');
        const store = tx.objectStore('cases');
        const request = store.getAll();
        request.onsuccess = () => {
          const cases = request.result || [];
          cases.sort((a, b) => new Date(b.date) - new Date(a.date));
          resolve(cases);
        };
        request.onerror = () => resolve([]);
      } catch (err) {
        console.error('[MailSentry Storage] Error getting cases:', err);
        resolve([]);
      }
    });
  },

  /**
   * Export complete vault to portable JSON for transfer or court evidence
   */
  async exportVaultArchive() {
    const blocks = await this.getAllBlocks();
    const cases = await this.getAllCases();
    const archive = {
      exportTimestamp: new Date().toISOString(),
      platform: 'MailSentry AI v2.0 Enterprise',
      jurisdiction: 'Bharatiya Sakshya Adhiniyam (BSA) 2023 Section 65B',
      blocksCount: blocks.length,
      casesCount: cases.length,
      ledger: blocks,
      cases: cases
    };
    return JSON.stringify(archive, null, 2);
  },

  /**
   * Clear vault (for forensic sanitization of field kits)
   */
  async clearAll() {
    await this.init();
    if (!this.db) return;

    return new Promise((resolve) => {
      const tx = this.db.transaction(['ledger', 'cases'], 'readwrite');
      tx.objectStore('ledger').clear();
      tx.objectStore('cases').clear();
      tx.oncomplete = () => resolve(true);
    });
  }
};
