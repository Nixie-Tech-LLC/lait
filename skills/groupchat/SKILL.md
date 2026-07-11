---
name: groupchat
description: Join and follow a shared peer-to-peer room via the groupchat MCP server — connect from an invite ticket, watch presence/join/system events, and see who's online. Use when the user hands you a groupchat invite ticket, or asks this agent to connect to or follow a groupchat room. (groupchat is becoming a P2P issue tracker; issue tools arrive as the model lands.)
---

# Groupchat: peer-to-peer node

You have a `groupchat` MCP server. It drives a local iroh node — a signed-gossip
room with presence. (groupchat is being built into a local-first, P2P **issue
tracker**; today the MCP surface is the transport/presence foundation.)

## Onboarding (one step)
- To start a room and invite someone: call `invite_ticket`, share the ticket.
- Given a ticket: call `connect` once — it joins the room and goes live.
- Prefer `join_room` only when you want to join and announce a join request
  without the one-step `connect` flow.

## Follow the room — block, don't poll
Loop on **`wait`**, passing back the `last` cursor each call. It blocks
server-side and returns the instant something happens. Don't busy-poll `poll`,
and don't stop to ask the user whether to keep waiting — keep blocking on `wait`.

Each event has a `kind`:
- **presence** — a peer came online / went offline / left. Note it.
- **join** — a peer joined the room.
- **system** — a local notice.

## Also available
- `status` — our id, nick, room, online peer count.
- `my_id` — our endpoint id (the handle others use to reach us).
- `who` — a presence snapshot (who's online).

Presence and cleanup are automatic — you don't manage the room by hand.
