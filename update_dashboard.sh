#!/bin/bash
sed -i 's/x-data="dashboardApp()"/x-data="dashboardApp()" @keydown.escape.window="closeModal()"/g' internal/web/templates/dashboard.html

# Add click handlers and hover styles to the 4 cards
sed -i 's/<div class="bg-\[#1a1a1a\] border border-zinc-800 rounded-2xl p-5 relative overflow-hidden group "/<div @click="openModal(\x27active_hunts\x27)" class="bg-[#1a1a1a] border border-zinc-800 rounded-2xl p-5 relative overflow-hidden group cursor-pointer hover:border-blue-500\/50 hover:bg-zinc-800\/50 transition-all "/g' internal/web/templates/dashboard.html

sed -i '0,/<div class="bg-\[#1a1a1a\] border border-zinc-800 rounded-2xl p-5 relative overflow-hidden group">/s//<div @click="openModal(\x27frozen_mules\x27)" class="bg-[#1a1a1a] border border-zinc-800 rounded-2xl p-5 relative overflow-hidden group cursor-pointer hover:border-blue-500\/50 hover:bg-zinc-800\/50 transition-all">/' internal/web/templates/dashboard.html

sed -i '0,/<div class="bg-\[#1a1a1a\] border border-zinc-800 rounded-2xl p-5 relative overflow-hidden group">/s//<div @click="openModal(\x27verified_takedowns\x27)" class="bg-[#1a1a1a] border border-zinc-800 rounded-2xl p-5 relative overflow-hidden group cursor-pointer hover:border-blue-500\/50 hover:bg-zinc-800\/50 transition-all">/' internal/web/templates/dashboard.html

sed -i 's/<div class="bg-gradient-to-br from-zinc-900\/50 to-zinc-900 border border-blue-600\/40 rounded-2xl p-5 relative overflow-hidden group">/<div @click="openModal(\x27threat_level\x27)" class="bg-gradient-to-br from-zinc-900\/50 to-zinc-900 border border-blue-600\/40 rounded-2xl p-5 relative overflow-hidden group cursor-pointer hover:border-blue-500 transition-all">/g' internal/web/templates/dashboard.html

