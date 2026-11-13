// Limit-warning detection and rolling-checkpoint counting. Pure functions over page text.
(function (root) {
  const TV = (root.TV = root.TV || {});
  const C = typeof module !== "undefined" ? require("./constants.js") : TV.constants;

  const PATTERNS = [
    /you(?:'|’)ve (?:reached|hit) (?:your|the) .{0,40}(?:limit|cap)/i,
    /(?:usage|message|rate|conversation|context) limit (?:reached|hit|exceeded)/i,
    /(?:approaching|nearing|close to) (?:your |the )?(?:usage |message |context |length )?limit/i,
    /(?:this )?conversation (?:is|has become|has gotten) (?:getting )?(?:too )?long/i,
    /reached the maximum (?:length|number of messages)/i,
    /you(?:'|’)re out of (?:messages|free messages)/i,
    /(?:limit|messages) (?:will )?reset(?:s)? (?:at|in|on)/i,
  ];

  function detectLimitWarning(noticeTexts) {
    for (const t of noticeTexts || []) {
      if (typeof t === "string" && t.length < 600 && PATTERNS.some((p) => p.test(t))) return true;
    }
    return false;
  }

  // Remind when the count of assistant turns crosses a multiple of `every` that we have not
  // already reminded for. Returns the new "last reminded" bucket, or null for no reminder.
  function checkpointDue(turns, every, lastBucket) {
    if (!Number.isInteger(every) || every < 1) return null;
    const bucket = Math.floor(turns / every);
    return bucket > 0 && bucket > (lastBucket || 0) ? bucket : null;
  }

  const api = { detectLimitWarning, checkpointDue, DEFAULT_EVERY: C.DEFAULT_CHECKPOINT_EVERY };
  if (typeof module !== "undefined") module.exports = api;
  else TV.limits = api;
})(globalThis);
