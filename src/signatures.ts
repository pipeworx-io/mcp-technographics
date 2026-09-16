/**
 * Technology signatures, written here rather than imported.
 *
 * WHY WE DID NOT USE WAPPALYZER'S RULESET. Every maintained ruleset in that
 * lineage is GPL-3.0 — `enthec/webappanalyzer` and `HTTPArchive/wappalyzer`
 * both are, and the popular MIT repos (`projectdiscovery/wappalyzergo`,
 * `rverton/webanalyze`) are MIT *code* that consumes those GPL-3.0 *rulesets*,
 * which does not launder the data's licence. Wappalyzer itself relicensed off
 * MIT before going commercial, and the forks inherited the copyleft.
 *
 * What is in this file is our own expression of publicly observable facts: that
 * Shopify sets a `_shopify_y` cookie, that Cloudflare answers with `cf-ray`,
 * that Next.js emits `__NEXT_DATA__`. Those facts are not anyone's property;
 * a particular curated database of them is. So this covers far fewer
 * technologies than a 29,000-entry commercial set and says so in every
 * response, rather than pretending to coverage it does not have.
 *
 * PATTERNS ARE DELIBERATELY TIGHT. The failure mode for a detector is a false
 * positive — /stripe/i against page text fires on the English word. Every
 * pattern here anchors on a host, a path, a cookie name, a header, or a
 * distinctive identifier, never on a bare product name in prose.
 */

export interface Signature {
  name: string;
  category: string;
  /** Matched against every script/link/iframe URL found in the markup. */
  url?: RegExp;
  /** Matched against the raw HTML. Anchor these hard. */
  html?: RegExp;
  /** [header name, optional value pattern]. Name match alone is a hit if no pattern. */
  header?: [string, RegExp?];
  /** Matched against Set-Cookie names. */
  cookie?: RegExp;
  /** Optional version capture, tried against the HTML. */
  version?: RegExp;
}

export const SIGNATURES: Signature[] = [
  // ── ecommerce ────────────────────────────────────────────────────────
  { name: 'Shopify', category: 'ecommerce', cookie: /_shopify_y|_shopify_s|_secure_session_id/, url: /cdn\.shopify\.com/i, html: /Shopify\.(shop|theme|routes)\b/ },
  { name: 'WooCommerce', category: 'ecommerce', url: /\/plugins\/woocommerce\//i, html: /woocommerce-(page|js|no-js)\b/ },
  { name: 'Magento', category: 'ecommerce', cookie: /X-Magento-Vary/i, html: /Magento_(Ui|Theme)\b|mage\/cookies/ },
  { name: 'BigCommerce', category: 'ecommerce', url: /cdn\d*\.bigcommerce\.com/i },
  { name: 'Wix Stores', category: 'ecommerce', html: /wix-stores/ },
  { name: 'Salesforce Commerce Cloud', category: 'ecommerce', url: /demandware\.(static|edgesuite)|\/on\/demandware\.store\//i },

  // ── payments ─────────────────────────────────────────────────────────
  { name: 'Stripe', category: 'payments', url: /js\.stripe\.com|checkout\.stripe\.com/i },
  { name: 'PayPal', category: 'payments', url: /(www|c)\.paypal(objects)?\.com\/(sdk|api)/i },
  { name: 'Braintree', category: 'payments', url: /js\.braintreegateway\.com/i },
  { name: 'Adyen', category: 'payments', url: /checkoutshopper-live\.adyen\.com|cdn\.adyen\.com/i },
  { name: 'Square', category: 'payments', url: /(web|js)\.squarecdn\.com|squareup\.com\/sdk/i },
  { name: 'Checkout.com', category: 'payments', url: /cdn\.checkout\.com/i },
  { name: 'Paddle', category: 'payments', url: /cdn\.paddle\.com/i },
  { name: 'Chargebee', category: 'payments', url: /js\.chargebee\.com/i },
  { name: 'Recurly', category: 'payments', url: /js\.recurly\.com/i },
  { name: 'Klarna', category: 'payments', url: /x\.klarnacdn\.net|js\.klarna\.com/i },
  { name: 'Affirm', category: 'payments', url: /cdn1?\.affirm\.com/i },
  { name: 'Shop Pay', category: 'payments', url: /shop\.app\/pay/i },

  // ── CMS ──────────────────────────────────────────────────────────────
  { name: 'WordPress', category: 'cms', url: /\/wp-(content|includes)\//i, html: /<link[^>]+wp-json|name="generator"[^>]+WordPress/i, version: /name="generator"[^>]+WordPress\s+([\d.]+)/i },
  { name: 'Drupal', category: 'cms', header: ['x-drupal-cache'], html: /drupal-settings-json|\/sites\/(all|default)\/(files|modules)\//i },
  { name: 'Joomla', category: 'cms', html: /name="generator"[^>]+Joomla|\/media\/jui\//i },
  { name: 'Ghost', category: 'cms', html: /name="generator"[^>]+Ghost/i },
  { name: 'Webflow', category: 'cms', html: /data-wf-(page|site)|name="generator"[^>]+Webflow/i },
  { name: 'Wix', category: 'cms', header: ['x-wix-request-id'], url: /static\.parastorage\.com/i },
  { name: 'Squarespace', category: 'cms', html: /static\.squarespace\.com|Static\.SQUARESPACE_CONTEXT/ },
  { name: 'Contentful', category: 'cms', url: /(images|cdn|assets)\.ctfassets\.net/i },
  { name: 'Sanity', category: 'cms', url: /cdn\.sanity\.io/i },
  { name: 'HubSpot CMS', category: 'cms', url: /cdn\d*\.hubspot\.net|hs-sites\.com/i },
  { name: 'Craft CMS', category: 'cms', header: ['x-powered-by', /Craft CMS/i] },
  { name: 'Prismic', category: 'cms', url: /prismic\.io|images\.prismic\.io/i },
  { name: 'Storyblok', category: 'cms', url: /a\.storyblok\.com/i },

  // ── JS frameworks ────────────────────────────────────────────────────
  { name: 'Next.js', category: 'javascript-framework', html: /__NEXT_DATA__|\/_next\/static\//, header: ['x-nextjs-cache'] },
  { name: 'Nuxt', category: 'javascript-framework', html: /__NUXT__|\/_nuxt\// },
  { name: 'React', category: 'javascript-framework', html: /data-reactroot|data-reactid|__REACT_DEVTOOLS/ },
  { name: 'Vue.js', category: 'javascript-framework', html: /data-v-[0-9a-f]{8}|__VUE_DEVTOOLS/ },
  { name: 'Angular', category: 'javascript-framework', html: /ng-version="([\d.]+)"|_nghost-/, version: /ng-version="([\d.]+)"/ },
  { name: 'Svelte', category: 'javascript-framework', html: /svelte-[0-9a-z]{6}\b|__sveltekit_/ },
  { name: 'Astro', category: 'javascript-framework', html: /astro-island|name="generator"[^>]+Astro/i },
  { name: 'Remix', category: 'javascript-framework', html: /__remixContext|__remixManifest/ },
  { name: 'Gatsby', category: 'javascript-framework', html: /___gatsby|\/page-data\/app-data\.json/ },
  { name: 'Alpine.js', category: 'javascript-framework', url: /alpinejs|alpine(\.min)?\.js/i, html: /x-data=["'][^"']*["'][^>]{0,200}x-(on:|bind:|show=)/ },
  { name: 'htmx', category: 'javascript-framework', url: /htmx(\.org|\.min)?\.js/i, html: /hx-(get|post|target|swap)=/ },
  { name: 'jQuery', category: 'javascript-library', url: /jquery[.-]?([\d.]+)?(\.min)?\.js/i, version: /jquery[.-]([\d.]+)(\.min)?\.js/i },
  { name: 'Ember.js', category: 'javascript-framework', html: /id="ember\d+"|ember-application/ },

  // ── analytics ────────────────────────────────────────────────────────
  { name: 'Google Analytics 4', category: 'analytics', url: /googletagmanager\.com\/gtag\/js/i, html: /gtag\('config',\s*'G-/ },
  { name: 'Google Tag Manager', category: 'tag-manager', url: /googletagmanager\.com\/gtm\.js/i, html: /GTM-[A-Z0-9]{4,}/ },
  { name: 'Segment', category: 'analytics', url: /cdn\.segment\.(com|io)/i, html: /analytics\.load\(/ },
  { name: 'Mixpanel', category: 'analytics', url: /cdn\d?\.mxpnl\.com/i },
  { name: 'Amplitude', category: 'analytics', url: /cdn\.amplitude\.com|amplitude\.com\/libs/i },
  { name: 'Heap', category: 'analytics', url: /cdn\.heap(analytics)?\.(com|io)/i },
  { name: 'PostHog', category: 'analytics', url: /(app|us|eu)\.posthog\.com|posthog\.com\/static/i },
  { name: 'Plausible', category: 'analytics', url: /plausible\.io\/js/i },
  { name: 'Fathom Analytics', category: 'analytics', url: /cdn\.usefathom\.com/i },
  { name: 'Matomo', category: 'analytics', url: /matomo\.(js|php)|piwik\.(js|php)/i },
  { name: 'Hotjar', category: 'analytics', url: /static\.hotjar\.com/i },
  { name: 'FullStory', category: 'analytics', url: /edge\.fullstory\.com/i },
  { name: 'Microsoft Clarity', category: 'analytics', url: /clarity\.ms/i },
  { name: 'Pendo', category: 'product-analytics', url: /cdn\.pendo\.io/i },
  { name: 'Mouseflow', category: 'analytics', url: /cdn\.mouseflow\.com/i },
  { name: 'Adobe Analytics', category: 'analytics', url: /assets\.adobedtm\.com|\/b\/ss\//i },

  // ── marketing automation / CRM ───────────────────────────────────────
  { name: 'HubSpot', category: 'marketing-automation', url: /js\.hs-(scripts|analytics|banner)\.com|js\.hsforms\.net/i, html: /_hsq\.push/ },
  { name: 'Marketo', category: 'marketing-automation', url: /munchkin\.marketo\.net|\.mktoresp\.com/i },
  { name: 'Salesforce Pardot', category: 'marketing-automation', url: /pi\.pardot\.com|pardot\.com\/pd\.js/i },
  { name: 'Klaviyo', category: 'marketing-automation', url: /static\.klaviyo\.com|a\.klaviyo\.com/i },
  { name: 'Mailchimp', category: 'marketing-automation', url: /chimpstatic\.com|list-manage\.com/i },
  { name: 'Braze', category: 'marketing-automation', url: /js\.appboycdn\.com|braze\.com\/api/i },
  { name: 'Customer.io', category: 'marketing-automation', url: /assets\.customer\.io/i },
  { name: 'ActiveCampaign', category: 'marketing-automation', url: /prism\.app-us1\.com|activehosted\.com/i },
  { name: 'Iterable', category: 'marketing-automation', url: /links\.iterable\.com/i },
  { name: 'Attentive', category: 'marketing-automation', url: /cdn\.attn\.tv/i },

  // ── support / chat ───────────────────────────────────────────────────
  { name: 'Intercom', category: 'live-chat', url: /widget\.intercom\.io|js\.intercomcdn\.com/i, html: /intercomSettings/ },
  { name: 'Drift', category: 'live-chat', url: /js\.driftt\.com/i },
  { name: 'Zendesk', category: 'support', url: /static\.zdassets\.com|zendesk\.com\/embeddable/i },
  { name: 'Freshdesk', category: 'support', url: /widget\.freshworks\.com|freshdesk\.com/i },
  { name: 'Crisp', category: 'live-chat', url: /client\.crisp\.chat/i },
  { name: 'Tawk.to', category: 'live-chat', url: /embed\.tawk\.to/i },
  { name: 'LiveChat', category: 'live-chat', url: /cdn\.livechatinc\.com/i },
  { name: 'Help Scout', category: 'support', url: /beacon-v2\.helpscout\.net/i },
  { name: 'Gorgias', category: 'support', url: /config\.gorgias\.chat/i },

  // ── advertising pixels ───────────────────────────────────────────────
  { name: 'Meta Pixel', category: 'advertising', url: /connect\.facebook\.net\/[^/]+\/fbevents\.js/i, html: /fbq\('init'/ },
  { name: 'Google Ads Conversion', category: 'advertising', html: /gtag\('config',\s*'AW-|googleadservices\.com\/pagead\/conversion/ },
  { name: 'LinkedIn Insight Tag', category: 'advertising', url: /snap\.licdn\.com\/li\.lms-analytics/i },
  { name: 'X (Twitter) Pixel', category: 'advertising', url: /static\.ads-twitter\.com\/uwt\.js/i },
  { name: 'TikTok Pixel', category: 'advertising', url: /analytics\.tiktok\.com/i },
  { name: 'Reddit Pixel', category: 'advertising', url: /www\.redditstatic\.com\/ads/i },
  { name: 'Microsoft Advertising UET', category: 'advertising', url: /bat\.bing\.com\/bat\.js/i },
  { name: 'Criteo', category: 'advertising', url: /static\.criteo\.net/i },
  { name: 'Taboola', category: 'advertising', url: /cdn\.taboola\.com/i },
  { name: 'Outbrain', category: 'advertising', url: /widgets\.outbrain\.com/i },

  // ── visitor identification / sales intelligence ──────────────────────
  // The GTM-relevant category: who is watching who visits.
  { name: '6sense', category: 'sales-intelligence', url: /j\.6sc\.co|epsilon\.6sense\.com/i },
  { name: 'Demandbase', category: 'sales-intelligence', url: /scripts\.demandbase\.com|api\.company-target\.com/i },
  { name: 'Clearbit Reveal', category: 'sales-intelligence', url: /x\.clearbitjs\.com|reveal\.clearbit\.com/i },
  { name: 'Leadfeeder', category: 'sales-intelligence', url: /sc\.lfeeder\.com/i },
  { name: 'Albacross', category: 'sales-intelligence', url: /serve\.albacross\.com/i },
  { name: 'RB2B', category: 'sales-intelligence', url: /ddwl4m2hdecbv\.cloudfront\.net|s\.rb2b\.com/i },
  { name: 'Warmly', category: 'sales-intelligence', url: /opps-widget\.getwarmly\.com|warmly\.ai/i },
  { name: 'Vector', category: 'sales-intelligence', url: /cdn\.vector\.co/i },
  { name: 'Qualified', category: 'sales-intelligence', url: /js\.qualified\.com/i },

  // ── scheduling ───────────────────────────────────────────────────────
  { name: 'Calendly', category: 'scheduling', url: /assets\.calendly\.com/i },
  { name: 'Chili Piper', category: 'scheduling', url: /js\.chilipiper\.com/i },
  { name: 'Cal.com', category: 'scheduling', url: /app\.cal\.com\/embed/i },
  { name: 'HubSpot Meetings', category: 'scheduling', url: /meetings\.hubspot\.com/i },

  // ── A/B testing & feature flags ──────────────────────────────────────
  { name: 'Optimizely', category: 'ab-testing', url: /cdn\.optimizely\.com/i },
  { name: 'VWO', category: 'ab-testing', url: /dev\.visualwebsiteoptimizer\.com/i },
  { name: 'LaunchDarkly', category: 'feature-flags', url: /app\.launchdarkly\.com|events\.launchdarkly\.com/i },
  { name: 'Statsig', category: 'feature-flags', url: /(api|featureassets)\.statsig\.com/i },
  { name: 'Kameleoon', category: 'ab-testing', url: /kameleoon\.(io|eu)/i },

  // ── consent management ───────────────────────────────────────────────
  { name: 'OneTrust', category: 'consent', url: /cdn\.cookielaw\.org|onetrust\.com\/consent/i },
  { name: 'Cookiebot', category: 'consent', url: /consent\.cookiebot\.com/i },
  { name: 'Osano', category: 'consent', url: /cmp\.osano\.com/i },
  { name: 'TrustArc', category: 'consent', url: /consent\.trustarc\.com|trustarc\.com\/notice/i },
  { name: 'Usercentrics', category: 'consent', url: /app\.usercentrics\.eu/i },
  { name: 'Termly', category: 'consent', url: /app\.termly\.io/i },
  { name: 'Klaro', category: 'consent', url: /klaro(\.min)?\.js/i },

  // ── CDN / hosting / edge ─────────────────────────────────────────────
  { name: 'Cloudflare', category: 'cdn', header: ['cf-ray'] },
  { name: 'Fastly', category: 'cdn', header: ['x-served-by', /cache-/i] },
  { name: 'Akamai', category: 'cdn', header: ['x-akamai-transformed'] },
  { name: 'Amazon CloudFront', category: 'cdn', header: ['x-amz-cf-id'] },
  { name: 'Vercel', category: 'hosting', header: ['x-vercel-id'] },
  { name: 'Netlify', category: 'hosting', header: ['x-nf-request-id'] },
  { name: 'GitHub Pages', category: 'hosting', header: ['server', /GitHub\.com/i] },
  { name: 'Heroku', category: 'hosting', header: ['via', /vegur/i] },
  { name: 'Amazon S3', category: 'hosting', header: ['server', /AmazonS3/i] },
  { name: 'Google Cloud Storage', category: 'hosting', header: ['x-goog-generation'] },
  // Fields are OR'd, not AND'd — the matcher returns on the first hit — so this
  // must key on something unique to Pages. Pairing it with cf-ray reported every
  // Cloudflare site as Pages, which is how shopify.com came back as one.
  { name: 'Cloudflare Pages', category: 'hosting', html: /[\w-]+\.pages\.dev/ },

  // ── web servers & runtimes ───────────────────────────────────────────
  { name: 'nginx', category: 'web-server', header: ['server', /^nginx/i], version: /nginx\/([\d.]+)/i },
  { name: 'Apache', category: 'web-server', header: ['server', /^Apache/i] },
  { name: 'Microsoft IIS', category: 'web-server', header: ['server', /^Microsoft-IIS/i] },
  { name: 'LiteSpeed', category: 'web-server', header: ['server', /LiteSpeed/i] },
  { name: 'Caddy', category: 'web-server', header: ['server', /^Caddy/i] },
  { name: 'Envoy', category: 'web-server', header: ['server', /^envoy/i] },
  { name: 'PHP', category: 'programming-language', header: ['x-powered-by', /^PHP/i] },
  { name: 'ASP.NET', category: 'web-framework', header: ['x-aspnet-version'] },
  { name: 'Ruby on Rails', category: 'web-framework', header: ['x-runtime'], cookie: /_rails_session|csrf_token/ },
  { name: 'Express', category: 'web-framework', header: ['x-powered-by', /^Express/i] },
  { name: 'Django', category: 'web-framework', cookie: /csrftoken|django_language/ },
  { name: 'Laravel', category: 'web-framework', cookie: /laravel_session|XSRF-TOKEN/ },

  // ── auth ─────────────────────────────────────────────────────────────
  { name: 'Auth0', category: 'authentication', url: /cdn\.auth0\.com|[\w-]+\.auth0\.com/i },
  { name: 'Okta', category: 'authentication', url: /[\w-]+\.okta(preview)?\.com|global\.oktacdn\.com/i },
  { name: 'Clerk', category: 'authentication', url: /clerk\.[\w.-]+\.dev|js\.clerk\.com/i },
  { name: 'Firebase', category: 'authentication', url: /www\.gstatic\.com\/firebasejs|firebaseapp\.com/i },

  // ── search ───────────────────────────────────────────────────────────
  { name: 'Algolia', category: 'search', url: /cdn\.jsdelivr\.net\/npm\/(algoliasearch|instantsearch)|[\w-]+-dsn\.algolia\.net/i },
  { name: 'Typesense', category: 'search', url: /typesense\.(org|net)/i },
  { name: 'Coveo', category: 'search', url: /static\.cloud\.coveo\.com/i },

  // ── video ────────────────────────────────────────────────────────────
  { name: 'Wistia', category: 'video', url: /fast\.wistia\.(net|com)/i },
  { name: 'Vimeo', category: 'video', url: /player\.vimeo\.com/i },
  { name: 'YouTube', category: 'video', url: /(www\.)?youtube(-nocookie)?\.com\/embed/i },
  { name: 'Mux', category: 'video', url: /stream\.mux\.com|src\.litix\.io/i },
  { name: 'Loom', category: 'video', url: /www\.loom\.com\/embed/i },

  // ── reviews & social proof ───────────────────────────────────────────
  { name: 'Trustpilot', category: 'reviews', url: /widget\.trustpilot\.com/i },
  { name: 'Yotpo', category: 'reviews', url: /staticw2\.yotpo\.com|cdn-widgetsrepository\.yotpo\.com/i },
  { name: 'Okendo', category: 'reviews', url: /d3hw6dc1ow8pp2\.cloudfront\.net|okendo\.io/i },
  { name: 'Judge.me', category: 'reviews', url: /cdn\d?\.judge\.me/i },
  { name: 'G2', category: 'reviews', url: /www\.g2crowd\.com\/track|track\.g2\.com/i },

  // ── documentation ────────────────────────────────────────────────────
  { name: 'GitBook', category: 'documentation', html: /name="generator"[^>]+GitBook/i, url: /gitbook\.(com|io)/i },
  // Bare /mintlify/i matched vercel.com, which merely NAMES Mintlify on the page.
  // Every pattern here has to key on something the technology EMITS.
  { name: 'Mintlify', category: 'documentation', url: /mintlify\.(com|dev)|mintlify-assets/i, html: /__MINTLIFY/ },
  { name: 'Docusaurus', category: 'documentation', html: /name="generator"[^>]+Docusaurus/i },
  { name: 'ReadMe', category: 'documentation', url: /readme\.io|cdn\.readme\.io/i },
  { name: 'Read the Docs', category: 'documentation', html: /readthedocs\.(org|io)/i },

  // ── fonts & assets ───────────────────────────────────────────────────
  { name: 'Google Fonts', category: 'font', url: /fonts\.(googleapis|gstatic)\.com/i },
  { name: 'Adobe Fonts (Typekit)', category: 'font', url: /use\.typekit\.net/i },
  { name: 'Font Awesome', category: 'font', url: /fontawesome|use\.fontawesome\.com/i },

  // ── error tracking / monitoring ──────────────────────────────────────
  { name: 'Sentry', category: 'monitoring', url: /browser\.sentry-cdn\.com|[\w-]+\.ingest\.sentry\.io/i },
  { name: 'Datadog RUM', category: 'monitoring', url: /www\.datadoghq-browser-agent\.com/i },
  { name: 'New Relic', category: 'monitoring', url: /js-agent\.newrelic\.com/i, html: /\bNREUM\b/ },
  { name: 'Bugsnag', category: 'monitoring', url: /d2wy8f7a9ursnm\.cloudfront\.net|bugsnag/i },
  { name: 'LogRocket', category: 'monitoring', url: /cdn\.lr-(ingest|in)\.com|cdn\.logrocket\.io/i },
];
