# Vulnerability fix report

| Site | # | Class | Location | Status | Tries | Before | After | Tests |
|---|---|---|---|---|---|---|---|---|
| payledger | 1 | xss | static/index.html:298 | FIXED | 2 | unescaped output in source (source-level check fails) | escaped in source | 26 passed in 36.60s |
| payledger | 2 | xss | static/index.html:423 | NEEDS HUMAN | 5 | unescaped output in source (source-level check fails) |  |  |

## payledger #1 (xss)

```diff
diff --git a/payledger/static/index.html b/payledger/static/index.html
index f4a91b4..d2c56ce 100644
--- a/payledger/static/index.html
+++ b/payledger/static/index.html
@@ -295,7 +295,7 @@ function renderLedger() {
     last = lbl;
     return head + `<button class="entry" data-id="${t.id}" style="animation-delay:${Math.min(n++, 8) * 30}ms">
       ${av(other, otherId)}
-      <span class="mid"><span class="memo">${t.memo || '&mdash;'}</span><span class="party">${incoming ? 'From' : 'To'} ${esc(other)} &middot; ${esc(clock(t.created_at))}</span></span>
+      <span class="mid"><span class="memo">${t.memo ? esc(t.memo) : '&mdash;'}</span><span class="party">${incoming ? 'From' : 'To'} ${esc(other)} &middot; ${esc(clock(t.created_at))}</span></span>
       <span class="amt ${incoming ? 'in' : 'out'}">${incoming ? '+' : '\u2212'}${inr(t.amount_cents)}</span>
     </button>`;
   }).join('');

```