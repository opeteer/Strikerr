#!/bin/bash
# 1. Update grid cols to 5
sed -i 's/<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">/<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">/' internal/web/templates/dashboard.html

# 2. Inject new card after Verified Takedowns
NEW_CARD='                <div @click="openModal(\x27officially_reported\x27)" class="bg-[#1a1a1a] border border-zinc-800 hover:border-blue-500 rounded-2xl p-5 relative overflow-hidden group cursor-pointer hover:scale-[1.02] transition-all duration-200">\n                    <div class="text-xs font-semibold text-zinc-300 uppercase tracking-wider mb-1 flex justify-between items-center">\n                        <span>Officially Reported</span>\n                        <i class="ph ph-arrow-up-right text-blue-500 opacity-0 group-hover:opacity-100 transition-opacity"></i>\n                    </div>\n                    <div class="text-4xl font-black text-white mt-2" x-text="stats.officially_reported">0</div>\n                    <div class="mt-3 text-xs text-zinc-400 font-medium">\n                        S\/MIME Dispatched\n                    </div>\n                </div>'

awk -v card="$NEW_CARD" '
/Hashed Evidence Vault Items/ {
    print
    getline
    print
    print card
    next
}
{ print }
' internal/web/templates/dashboard.html > dashboard_tmp.html
mv dashboard_tmp.html internal/web/templates/dashboard.html

# 3. Add officially_reported to initial state in JS
sed -i 's/verified_takedowns: 0,/verified_takedowns: 0,\n                    officially_reported: 0,/g' internal/web/templates/dashboard.html
