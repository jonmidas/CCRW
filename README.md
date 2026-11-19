# CCRW Rollcall

Attendance register for meetings. Search people by name or phone number as they arrive and register them. Group and subgroup strength updates live, with each group's head. When the meeting ends you get a final absent list.

- **Frontend:** `public/index.html`, one static page with no build step.
- **API and data:** `src/worker.js`, a Cloudflare Worker with a D1 database (`ccrw`). It also serves the page on Cloudflare.
- **Vercel:** serves the same `public/` folder and calls the Worker API directly (CORS).

## How it works

- **Members:** import a spreadsheet (.xlsx or .csv) with columns **Name, Phone, Group, Subgroup, Role**. Role can be "Group head" or "Subgroup head". Groups and subgroups are created automatically, and anyone without a group goes into **Not paired yet**.
- **Check in:** start a meeting, type a name or phone number, then press Enter or click Register. If someone isn't on the register, **Add & register** puts them in *Not paired yet*.
- **Groups:** present out of total for every group and subgroup, plus their heads.
- **Absent:** everyone not registered, grouped by group with the group head's contact. **End meeting** makes the list final. You can download it, print it or copy it.
- Every desk unlocks with a shared **desk passcode**, and you can change it on the Meetings tab. After 10 wrong attempts from one address, that address is locked out for 15 minutes.
- Each desk queues its changes if the internet drops and sends them when it's back.

## Local development

```sh
npm install
npm run db:local          # create tables in the local D1
npx wrangler d1 execute ccrw --local --command "INSERT OR REPLACE INTO settings VALUES ('passcode_sha256', '<sha256 of your passcode>', 0)"
npm run dev               # http://localhost:8787
```

## Deploy

- **Cloudflare:** `npx wrangler deploy`, or connect this repo under Workers & Pages → Import a repository. Pushes to `main` then deploy automatically.
- **Vercel:** import the repo. `vercel.json` serves `public/` as a static site.

The database schema is in `schema.sql`.
