const fs = require('fs');
const file = 'internal/web/templates/dashboard.html';
let html = fs.readFileSync(file, 'utf8');

const modalHtml = `
            <!-- Interactive Detail Modal -->
            <div x-show="activeModal" style="display: none;"
                 class="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6"
                 x-transition:enter="transition ease-out duration-200"
                 x-transition:enter-start="opacity-0"
                 x-transition:enter-end="opacity-100"
                 x-transition:leave="transition ease-in duration-150"
                 x-transition:leave-start="opacity-100"
                 x-transition:leave-end="opacity-0">
                
                <!-- Backdrop -->
                <div class="fixed inset-0 bg-[#0c0a09]/80 backdrop-blur-sm" @click="closeModal()"></div>

                <!-- Modal Panel -->
                <div class="bg-[#141414] border border-zinc-800 rounded-2xl shadow-2xl w-full max-w-4xl max-h-[85vh] flex flex-col relative z-10 transform transition-all"
                     x-transition:enter="transition ease-out duration-300"
                     x-transition:enter-start="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
                     x-transition:enter-end="opacity-100 translate-y-0 sm:scale-100"
                     x-transition:leave="transition ease-in duration-200"
                     x-transition:leave-start="opacity-100 translate-y-0 sm:scale-100"
                     x-transition:leave-end="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95">
                    
                    <div class="px-6 py-4 border-b border-zinc-800 flex justify-between items-center bg-[#1a1a1a] rounded-t-2xl">
                        <h2 class="text-lg font-bold text-white flex items-center gap-2">
                            <i class="ph-fill ph-info text-blue-500"></i>
                            <span x-text="modalData ? modalData.title : 'Loading...'"></span>
                        </h2>
                        <button @click="closeModal()" class="text-zinc-400 hover:text-white transition-colors">
                            <i class="ph ph-x text-xl"></i>
                        </button>
                    </div>

                    <div class="p-6 overflow-y-auto flex-1 custom-scrollbar">
                        <template x-if="modalLoading">
                            <div class="flex justify-center items-center h-32">
                                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                            </div>
                        </template>

                        <template x-if="!modalLoading && modalData">
                            <div class="space-y-6">
                                <div class="bg-blue-900/10 border border-blue-500/20 rounded-xl p-4 text-sm text-blue-200 leading-relaxed">
                                    <strong class="text-blue-400 font-mono text-xs block mb-1">SOC DOCUMENTATION</strong>
                                    <span x-text="modalData.description"></span>
                                </div>

                                <div class="bg-[#1a1a1a] border border-zinc-800 rounded-xl overflow-hidden">
                                    <table class="w-full text-left text-sm text-zinc-300">
                                        <thead class="bg-zinc-900/50 text-xs uppercase text-zinc-400 font-mono border-b border-zinc-800">
                                            <tr>
                                                <th class="px-4 py-3">Detail Key / ID</th>
                                                <th class="px-4 py-3">Information / Value</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-zinc-800">
                                            <template x-for="item in modalData.items">
                                                <tr class="hover:bg-zinc-800/30">
                                                    <td class="px-4 py-3 font-mono text-xs text-blue-400" x-text="item.DomainName || item.AccountNumber || item.DOMHash || item.metric"></td>
                                                    <td class="px-4 py-3 text-zinc-300" x-text="item.TargetedBrand || item.InstitutionName || item.value || 'N/A'"></td>
                                                </tr>
                                            </template>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
            </div>
`;

html = html.replace('</main>', modalHtml + '\n        </main>');

// Update Alpine component
const stateToAdd = `
                activeModal: null,
                modalData: null,
                modalLoading: false,
                openModal(type) {
                    this.activeModal = type;
                    this.modalLoading = true;
                    this.modalData = null;
                    fetch('/api/v1/metrics/details?type=' + type)
                        .then(res => res.json())
                        .then(data => {
                            this.modalData = data;
                            this.modalLoading = false;
                        });
                },
                closeModal() {
                    this.activeModal = null;
                },`;

html = html.replace('recentMules: [],', 'recentMules: [],' + stateToAdd);

fs.writeFileSync(file, html);
