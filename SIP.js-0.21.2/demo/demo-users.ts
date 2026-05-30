// To allow multiple users to run the demo without playing a game of chatroulette,
// we give both callers in the demo a random token and then only make calls between
// users with these token suffixes. So, you still might run into a user besides yourself.

function getCookie(key: string): string {
  const re = new RegExp("(?:(?:^|.*;\\s*) ?" + key + "\\s*=\\s*([^;]*).*$)|^.*$");
  return document.cookie.replace(re, "$1");
}

function randomString(length: number, chars: string): string {
  let result = "";
  for (let i = length; i > 0; --i) {
    result += chars[Math.round(Math.random() * (chars.length - 1))];
  }
  return result;
}

// Each session gets a token that expires 1 day later. This is so we minimize
// the number of users we register for the SIP domain, because SIP hosts
// generally have limits on the number of registered users you may have in total
// or over a period of time.
let token = getCookie("onsipToken");
if (token === "") {
  token = randomString(32, ["0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"].join(""));
  const d = new Date();
  d.setTime(d.getTime() + 1000 * 60 * 60 * 24); // expires in 1 day
  document.cookie = "onsipToken=" + token + ";" + "expires=" + d.toUTCString() + ";";
}

// The demos uses unauthenticated users on the "sipjs.onsip.com" demo domain.
// The demos uses OnSIP's WebSocket Server which hosts the "sipjs.onsip.com" demo domain.
const domain = "sipjs.onsip.com";

export const nameAlice = "Alice";
export const uriAlice = "sip:alice." + token + "@" + domain;
export const webSocketServerAlice = "wss://edge.sip.onsip.com";

export const nameBob = "Bob";
export const uriBob = "sip:bob." + token + "@" + domain;
export const webSocketServerBob = "wss://edge.sip.onsip.com";
