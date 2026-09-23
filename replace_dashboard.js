const fs = require('fs');
const file = 'internal/web/templates/dashboard.html';
let html = fs.readFileSync(file, 'utf8');

// 1. Replace the header for Manual Scan & Purge
const oldHeader = `<header class="h-16 bg-[#1a1a1a] border-b border-zinc-800 flex items-center justify-between px-6 flex-shrink-0 z-10">
            <div class="flex items-center">
                <button @click="sidebarOpen = !sidebarOpen" class="md:hidden text-zinc-400 hover:text-zinc-300 mr-4 focus:outline-none">
                    <i class="ph ph-list text-2xl"></i>
                </button>
                <div class="flex items-center bg-[#141414] rounded-xl border border-zinc-800 px-3.5 py-1.5 w-72 focus-within:border-blue-500/60 transition-all">
                    <i class="ph ph-magnifying-glass text-blue-500/70 mr-2"></i>
                    <input type="text" placeholder="Search live target, account..." class="bg-transparent border-none focus:outline-none text-xs w-full text-white placeholder-zinc-500">
                </div>
            </div>

            <div class="flex items-center space-x-4">
                <span class="hidden sm:inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-bold bg-zinc-800 text-zinc-300 border border-zinc-700/60">
                    <span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                    STATUS: <span x-text="stats.threat_level">NORMAL</span>
                </span>
            </div>
        </header>`;

const newHeader = `<header class="h-16 bg-[#1a1a1a] border-b border-zinc-800 flex items-center justify-between px-6 flex-shrink-0 z-10">
            <div class="flex items-center w-full max-w-2xl">
                <button @click="sidebarOpen = !sidebarOpen" class="md:hidden text-zinc-400 hover:text-zinc-300 mr-4 focus:outline-none">
                    <i class="ph ph-list text-2xl"></i>
                </button>
                <div class="flex items-center bg-[#141414] rounded-xl border border-zinc-800 px-2 py-1.5 w-full focus-within:border-blue-500/60 transition-all">
                    <i class="ph ph-crosshair text-blue-500/70 mr-2 ml-2"></i>
                    <input x-model="manualScanUrl" @keydown.enter="runManualScan()" type="text" placeholder="Enter Target URL to run Active Target Scan..." class="bg-transparent border-none focus:outline-none text-xs w-full text-white placeholder-zinc-500" :disabled="isScanning">
                    <button @click="runManualScan()" :disabled="isScanning" class="ml-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-[10px] font-bold px-4 py-1.5 rounded-lg transition-colors flex items-center">
                        <span x-show="!isScanning">SCAN TARGET</span>
                        <span x-show="isScanning" class="flex items-center gap-1"><i class="ph ph-spinner animate-spin"></i> SCANNING</span>
                    </button>
                </div>
            </div>

            <div class="flex items-center space-x-4 shrink-0">
                <button @click="purgeDatabase()" class="bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/20 px-3 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1">
                    <i class="ph ph-trash"></i> PURGE DB
                </button>
                <span class="hidden sm:inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-bold bg-zinc-800 text-zinc-300 border border-zinc-700/60">
                    <span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                    <span x-text="stats.threat_level">NORMAL</span>
                </span>
            </div>
        </header>`;
html = html.replace(oldHeader, newHeader);


// 2. Replace the table section
const oldTable = `<div class="p-5 border-b border-zinc-800 flex justify-between items-center bg-[#1a1a1a]">
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="ph ph-list-bullets text-blue-500"></i> Live Discovered Mule Accounts & Threats
                    </h3>
                    <span class="text-xs font-mono text-zinc-300 bg-zinc-800 px-2.5 py-1 rounded-full border border-zinc-700">REAL DATABASE</span>
                </div>
                
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm text-zinc-300">
                        <thead class="bg-[#141414] text-xs uppercase text-zinc-300/80 font-mono border-b border-zinc-800">
                            <tr>
                                <th class="px-6 py-4">Account Number</th>
                                <th class="px-6 py-4">Institution</th>
                                <th class="px-6 py-4">Source Target URL</th>
                                <th class="px-6 py-4">Threat Score</th>
                                <th class="px-6 py-4">Status</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-zinc-800">
                            <template x-for="mule in recentMules" :key="mule.ID">
                                <tr class="hover:bg-zinc-800/50 transition-colors">
                                    <td class="px-6 py-4 font-mono font-bold text-zinc-300" x-text="mule.AccountNumber"></td>
                                    <td class="px-6 py-4 font-medium text-white" x-text="mule.InstitutionName"></td>
                                    <td class="px-6 py-4 text-zinc-400 font-mono text-xs" x-text="mule.SourceURL"></td>
                                    <td class="px-6 py-4 font-extrabold text-blue-500" x-text="mule.RiskScore + ' / 100'"></td>
                                    <td class="px-6 py-4">
                                        <span class="px-3 py-1 bg-zinc-800 text-zinc-300 border border-zinc-700 text-[10px] uppercase font-bold rounded-full shadow-sm" x-text="mule.Status"></span>
                                    </td>
                                </tr>
                            </template>
                            <tr x-show="recentMules.length === 0">
                                <td colspan="5" class="px-6 py-8 text-center text-zinc-500 font-mono text-xs">
                                    Scanning target streams... Discovered threats will appear here automatically.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>`;

const newTable = `<div class="p-5 border-b border-zinc-800 flex justify-between items-center bg-[#1a1a1a]">
                    <h3 class="text-base font-bold text-white flex items-center gap-2">
                        <i class="ph ph-list-bullets text-blue-500"></i> Discovered Mule Accounts & Threats
                    </h3>
                    <div class="flex gap-2">
                        <button @click="muleFilter = 'all'" :class="muleFilter === 'all' ? 'bg-blue-600 text-white' : 'bg-zinc-800 text-zinc-400'" class="px-3 py-1 text-xs font-bold rounded-md transition-colors">ALL</button>
                        <button @click="muleFilter = 'bank'" :class="muleFilter === 'bank' ? 'bg-blue-600 text-white' : 'bg-zinc-800 text-zinc-400'" class="px-3 py-1 text-xs font-bold rounded-md transition-colors">BANKS</button>
                        <button @click="muleFilter = 'ewallet'" :class="muleFilter === 'ewallet' ? 'bg-blue-600 text-white' : 'bg-zinc-800 text-zinc-400'" class="px-3 py-1 text-xs font-bold rounded-md transition-colors">E-WALLETS</button>
                    </div>
                </div>
                
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm text-zinc-300">
                        <thead class="bg-[#141414] text-xs uppercase text-zinc-300/80 font-mono border-b border-zinc-800">
                            <tr>
                                <th class="px-6 py-4">Account Number</th>
                                <th class="px-6 py-4">Institution</th>
                                <th class="px-6 py-4">Source Target URL</th>
                                <th class="px-6 py-4">Status</th>
                                <th class="px-6 py-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-zinc-800">
                            <template x-for="mule in filteredMules" :key="mule.ID">
                                <tr class="hover:bg-zinc-800/50 transition-colors">
                                    <td class="px-6 py-4 font-mono font-bold text-zinc-300" x-text="mule.AccountNumber"></td>
                                    <td class="px-6 py-4 font-medium text-white">
                                        <div class="flex items-center gap-2">
                                            <span x-text="mule.InstitutionName"></span>
                                            <span class="text-[9px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400" x-text="mule.InstitutionType"></span>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 text-zinc-400 font-mono text-xs truncate max-w-[200px]" x-text="mule.SourceURL"></td>
                                    <td class="px-6 py-4">
                                        <span class="px-2.5 py-1 bg-zinc-800 text-zinc-300 border border-zinc-700 text-[10px] uppercase font-bold rounded-full shadow-sm" x-text="mule.Status"></span>
                                    </td>
                                    <td class="px-6 py-4 text-right space-x-2">
                                        <button @click="freezeAccount(mule.ID)" class="text-xs bg-red-500/10 hover:bg-red-500 border border-red-500/30 text-red-400 hover:text-white px-2 py-1 rounded transition-colors">Freeze</button>
                                        <a :href="'/api/v1/dossier/download?id=' + mule.ID" class="text-xs bg-blue-500/10 hover:bg-blue-500 border border-blue-500/30 text-blue-400 hover:text-white px-2 py-1 rounded transition-colors inline-block">PDF</a>
                                    </td>
                                </tr>
                            </template>
                            <tr x-show="filteredMules.length === 0">
                                <td colspan="5" class="px-6 py-8 text-center text-zinc-500 font-mono text-xs">
                                    No records found for selected filter.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>`;
html = html.replace(oldTable, newTable);


// 3. Add the logic to the Alpine component
const oldAlpineProps = `                modalData: null,
                modalLoading: false,
                lastTotalMules: null,
                historyLabels: [],
                historyData: [],`;

const newAlpineProps = `                modalData: null,
                modalLoading: false,
                lastTotalMules: null,
                historyLabels: [],
                historyData: [],
                manualScanUrl: '',
                isScanning: false,
                muleFilter: 'all',
                get filteredMules() {
                    if (this.muleFilter === 'all') return this.recentMules;
                    return this.recentMules.filter(m => m.InstitutionType.toLowerCase().includes(this.muleFilter));
                },
                purgeDatabase() {
                    if(confirm('WARNING: This will permanently purge ALL database records and reset counters to 0. Are you sure?')) {
                        fetch('/api/v1/system/purge', {method: 'POST'})
                        .then(() => {
                            this.fetchStats();
                            alert('Database successfully purged.');
                        });
                    }
                },
                runManualScan() {
                    if (!this.manualScanUrl) return;
                    this.isScanning = true;
                    fetch('/api/v1/scan/target', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({url: this.manualScanUrl})
                    })
                    .then(res => res.json())
                    .then(data => {
                        this.isScanning = false;
                        if(data.status === 'success') {
                            this.manualScanUrl = '';
                            this.fetchStats();
                        } else {
                            alert(data.message || data.error);
                        }
                    })
                    .catch(() => this.isScanning = false);
                },
                freezeAccount(id) {
                    alert('Action dispatched: Takedown/Freeze request queued for Account ID: ' + id);
                },`;
html = html.replace(oldAlpineProps, newAlpineProps);

fs.writeFileSync(file, html);
console.log('dashboard.html completely updated');
