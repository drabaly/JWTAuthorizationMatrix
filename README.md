# JWT Authorization Matrix

A Burp Suite extension for testing JWT-based authorization. It builds a matrix of
endpoints × users (identified by a JWT claim) showing the HTTP status codes each user
received, then replays every captured request with every user's token so access-control
gaps stand out.

## Features

- Live capture from Proxy, Repeater and Intruder (selectable), or rebuild from Proxy history
  with an optional URL regex
- JWT read from the `Authorization: Bearer` header or a named cookie
- Configurable user claim, including nested claims (`user.email`)
- Endpoints grouped by method + path; `[+]` expands query-string variants
- Colour-coded cells with configurable status-code groups (`2xx`, `401`, `2xx,5xx`, ...)
- Click a cell to inspect its requests and responses in Burp's message viewers
- Multi-select + right-click to delete endpoints
- Multithreaded, cancellable replay of all captured requests with each user's token
- CSV / JSON export of both matrices
- Settings persist across Burp restarts (tokens are never saved)

## Installation

1. Download the [Jython standalone JAR](https://www.jython.org/download.html) (2.7.x).
2. In Burp, `Extensions` → `Extensions settings` → `Python environment`: select the JAR.
3. `Extensions` → `Installed` → `Add`, type `Python`, select `JWTAuthMatrix.py`.

## Usage

The extension adds a **JWT Auth Matrix** tab with three sub-tabs.

### Settings

- **Capture**: which Burp tools feed the matrix.
- **Token location**: Authorization header or cookie name. Also used when replaying.
- **User claim**: JWT claim identifying users (default `sub`). Applies to new captures;
  use *Rebuild from Proxy history* to regroup existing traffic.
- **Colours**: edit status-code groups, one per line as `pattern:0xRRGGBB:label`. Click a
  legend swatch to change a single colour.

### Matrix

Browse the application as different users, or click **Rebuild from Proxy history**
(optionally restricted by *History URL regex*). You can also right-click messages anywhere
in Burp → **Send to JWT Authorization Matrix**.

- Click a status cell to open the matching requests/responses.
- Click an endpoint with `[+]` to show its query-string variants.
- Click a column header to sort (ascending ▲, descending ▼, then capture order). Variants
  stay under their endpoint; user columns sort by status codes, then counts.
- Select rows and right-click to delete endpoints.
- **Remove duplicates** keeps, for each user, one request per identical method + URL
  (query string included) + body. This also shortens the replay.
- Type in *Filter endpoints* to narrow the view.

### Replay

The token table fills automatically with the latest JWT seen for each user; you can add,
edit or delete rows. **Add anonymous user** adds an `<anonymous>` row whose requests are
replayed with the JWT removed, to spot endpoints that need no authentication. Set the thread count (1–50) and click
**Replay all captured requests with these tokens**. Results appear in the replay matrix
below the table as they arrive. The replay can be cancelled at any time.

## Development

Single-file Jython 2.7 extension using Burp's legacy Extender API. The tests run the real
extension under Jython in headless Swing, with fakes for Burp's callbacks:

```sh
./tests/run_tests.sh   # override JYTHON_JAR / BURP_JAR if not under /opt/BurpSuitePro
```

## License

MIT

## Author

Alexis Pain
