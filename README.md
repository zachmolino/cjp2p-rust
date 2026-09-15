This builds on the following standards:

- https://github.com/kermit4/LCDP Lowest Common Denominator Protocol
- https://en.wikipedia.org/wiki/WebSocket
- https://en.wikipedia.org/wiki/User_Datagram_Protocol (UDP)
- https://en.wikipedia.org/wiki/HTTP
- https://rust-lang.org/

The current target audience is developers, so the UI is minimal and not well documented.   If you don't intend to develop p2p software, this repo is probably not for you, though the sample implementations are quite powerful.  

APK/Termux builds tested to not use much battery / wakeup timer is 2s (unless you're hosting a bunch of files AND people are downloading them a lot, neither of which is likely right now.)

Useful things this CLI provides without any other UI
- /publish path  (copy file to cjp2p/origin/ and print its URL, updates will propagate)
- /share path  (serve file by BLAKE3 and sha256 hash from cjp2p/public/ 
- /get [hash]

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it, except for /latest/ which are ordinary names that get checked for changes and published by hash in /public/, and the requester is sent the latest hash. (So you have distributed updateable content by your public key.  Make yourself a home page, call it index.html .)

If you create .allow_remote_http in the directory you run this, the next time it starts it will allow any IP to connect to the HTTP port, but it will only serve files you already have, it can't cause it to download anything new, and doesn't have any of special access that localhost does. As of this writing that means it will refuse websockets too. I run it with .allow_remote_http so I think its safe, but I have no crypto keys laying around to worry about.

If you want to run this privately, for example among a fixed set of peers on a tailnet, and keep it off the wider public network:

- Create .no_bootstrap in the directory you run this and it will not add the built-in public bootstrap peers on startup, and will not look for peers on the local network either (no broadcast or multicast to 24254). It also forgets peers saved from earlier runs, so a node that was once public does not keep dialling the peers it met then.
- Create .no_port_mapping and it will not attempt UPnP or PCP port mapping (no SSDP discovery, no PCP requests, and no periodic re-mapping every 20 minutes).
- Create .static_peers with one "ip:port" per line (blank lines and lines starting with # are ignored) and it will add those as peers on startup instead.


# building (optional)

- https://github.com/kermit4/cjp2p-rust/ 

make release

# running

- https://github.com/kermit4/cjp2p-rust/releases if you didn't build it above

./target/release/cjp2p

or 

RUST_LOG=info ./target/release/cjp2p

or 

RUST_LOG=warn ./target/release/cjp2p

Then type /help or go to http://localhost:24255/ where all the on-network links are

This uses about 400MB/day 

This also works great on Android.  It does use "StartForeground" but the base maintenance timer is ~2 seconds on Android ( ~1 elsewhere ).  I don't notice any more battery drain with it running than without on mobile or wifi.

# updating

`/update` -- if the exe is in a /target/ path it will get a bundle off the network and build and run it, otherwise it will get the latest release (verified by Github to match the source at the time) off Github.

If it's not running, `git pull` then `make`

# hints

[WEBSOCKET_API.md] WEBSOCKET_API.md for web devs who just want to write browser side p2p apps (that even work on a LAN without internet)
[build your own p2p game in minutes quick start](quickstart_build_a_p2p_game_with_one_prompt.md)
[build your own p2p twitter in minutes quick start](quickstart_build_a_p2p_twitter_with_one_prompt.md)


Try /get c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b (its ubuntu-24.04.3-live-server-amd64.iso ) and watch it come from two places with iftop


# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
- make it easy for other people to build on, make easy for UI devs on websockets
## UI
-   webtransport?
## scarcity related
- proof of latency? signature chain of somewhat verifiable latency?
- valuable numbers? (PoW?  or valuable just because the issuer, based on their public key, limits the issuance.  every person their own "coin" as value derived from their reputation?  reputation granting fungible negotiable scarcity? be your own CENTRAL bank!)
- ipv4 scarcity, that worked fine until 2000, just do that, for ipv6 its all in 2... 3.... (2000::/3) . the next 32 are about as in ipv4.
- read this again https://howtofixtheweb.com/
- once there is economics, sell services
### reputation
- thanks based reputation. auto-thanks on succesful get.
- web of trust - direct referal trust or public reputation..and is that the scarcity   reputation is not absolute, its from your point of view, that solves sybil attacks
## public collaboration 
- needs some scarcity, eventually, right?  to not be spam?  as long as the spam cant be automated without limit
- news feed - or extend chirp.html
- reviews of content
- reviews of anything
- toy/game p2p virtual universe
- polls, approval voting style
- some equivalent of wikipedia.. no concensus needed, DAG, fork if they want, or agree if they want. forks forever or people sane enough to sync up.  each name space can have a popularity 
## unnsorted
- make it do what i actually do each day, check for news basically, from friends or weigthed by importance/distance. like /trending but scoped/weighted.  user defined algorithm. get /trending into a nice /UI ..  make it do it well, easy, streamlined, in browser, and to select 2nd and third most trending, and most popular, etc.
- any aggressive scans should monitor latency and loss consequences and throttle both max bw and max hosts/sec because they are often separate limits on consumer routers even without NAT (DMZ/ipv6)
- dot file, env var, commmand line options..too many ways to pass options
- lcdp crate now? send to ed25519 and big hash getter are basic legos .. the killer app for this i think is a lib that is a drop in socket replacement that takes a pub (oh https://www.iroh.computer/ does that), or maybe libp2p semantics..look into how you actually send a message with libp2p, or transport for it as long as the app can still direct message on the socket.
- just default stream url for people not dated
- it is time to make various mini stand-alone apps instead of this one big thing, separate repos, real users of the protocol .. except that peer discover is evolving, maybe thats the lib part?..make a standalone pong apk? 
- focus on enabling devs, i've done enough demoing.. general dev UX .. for devs though ..DX..more walkthroughs, speedruns, how to build something, native, html, some overlap, no overlap, different languages ..start from total noob, dev exp
- at some point, /latest should use blake3 not sha, for pre-finished relaying
- all the "metadata" dirs/files created by caching what others are searching for rather inefficiently and by ContentList::receive is sort of a DOS-ish situation potentially
- verify blake3 tree should be a thread probably, for massive files to not pause the app
- shorter path to doing stuff in this and protocol readme, like for non-technical people to make p2p apps they can use right away

- metadata
- channels, like a stream but multiple senders, with consensus (like a blockchain or DAG)
- channels, like a stream but multiple senders, without consensus 
- economics to incentivize resource sharing
- chat message white or black listing to avoid spam, and sharing the lists
- synchronized media playback between peers (i dont know why, it just seems fun...a shared experience, at a distance, would go well with group chats, like the 1990s when video was usually in sync)
- make initial readme really short, and file list, very non-intimidiating, the base is really just UDP plus arrays of eexternally tagged values. put write_ups in their own dir, dont evne link to it from the README
- super simple demo apps claude made are way too big ..maybe cut out the anti-spoof for now.
- fork a web browser to give direct udp access?..qutebrowser? -- AI says this is not easy because its not merely disabled, but doesnt exist in browser side JS
- assets, any kind of assets, get creative, certainly cryptography will be involved, but hopefully not another blockchain..signature histories dont need blocks and are their own chain
- backend message retransmit timer as a service to the web apps, instead of web side because they time out, for chirp, group chat, i think thats all, it could even be to the set/group not just the hosts known to the web side at the time?  though i like the app being fully UI side, this could be a mess later
- PleaseAlwaysReturnThisMessage should be shorter since this is sent unverified
- add VSTs to DAW?
- make chirp like group_chat_stream ?
- forums? using /stream/ too like the group_chat_stream?
- why arent streams a POST from the browser?  oh well maybe to handle restarts of the backend?  no, it can just repost..i don think there is a good reason really.
