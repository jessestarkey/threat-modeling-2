# Vendored Font Notice

`FreeSans.otf`, `FreeSansBold.otf`, `FreeSansOblique.otf`, `FreeSansBoldOblique.otf` are part of [GNU FreeFont](https://savannah.gnu.org/projects/freefont/) (version 0412.2268), copyright 2002-2012 the GNU FreeFont contributors. Licensed under the [GNU General Public License](http://www.gnu.org/copyleft/gpl.html) with the standard font-embedding exception (permits embedding in a rendered document -- exactly this repository's use, via WeasyPrint -- without that document itself becoming subject to the GPL).

## Why these are vendored here instead of installed via apt

`threagile_dfd_to_html.py` draws diagram label text as `font-family="FreeSans, sans-serif"` (`FONT` constant) specifically because that's what fontconfig resolves `"Verdana"` to inside the pinned `threagile/threagile:0.9.1` image -- the same image whose `dot` binary computes the node/label box sizes these diagrams' text has to fit inside. Rendering with any other font, even one with fairly close metrics, risks overflowing those pre-computed boxes; `wrap_and_fit()`'s own word-wrap estimate is calibrated for FreeSans specifically. Confirmed directly: `docker run --entrypoint sh threagile/threagile:0.9.1 -c 'fc-match Verdana'` resolves to `FreeSans.otf`.

Normally this was installed via the `fonts-freefont-ttf` apt package. On an air-gapped GitLab runner without that package mirrored in an internal Nexus/apt proxy, these 4 files are extracted directly from the pinned Threagile image instead (`docker cp` from `/usr/share/fonts/freefont/` -- guaranteeing byte-identical metrics to what Threagile itself used, not just a same-named font from a possibly different build/version) and vendored here, installed at job/report-render time from the repo checkout rather than from an apt package -- see `gitlab/workflows/threagile-modular.gitlab-ci.yml`'s and `threagile-monolithic.gitlab-ci.yml`'s report jobs.

Only the `FreeSans` family (not `FreeMono`/`FreeSerif`, also part of the same GNU FreeFont release) is vendored, since it's the only one this repository's code actually references.

## Regenerating

If the pinned Threagile version ever changes, re-extract from the new image rather than assuming these are still current:

```sh
CID=$(docker create threagile/threagile:<new-version>)
docker cp "$CID:/usr/share/fonts/freefont/FreeSans.otf" .
docker cp "$CID:/usr/share/fonts/freefont/FreeSansBold.otf" .
docker cp "$CID:/usr/share/fonts/freefont/FreeSansOblique.otf" .
docker cp "$CID:/usr/share/fonts/freefont/FreeSansBoldOblique.otf" .
docker rm "$CID"
```
