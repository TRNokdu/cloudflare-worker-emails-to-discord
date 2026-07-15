import { createRemoteJWKSet, jwtVerify } from "jose";

const PostalMime = require("postal-mime");
const { convert } = require("html-to-text");

// It's 4096
const DISCORD_EMBED_LIMIT = 4096;
// This may be higher if your server is boosted to level 2, it should be 50MB. If your server is boosted to level 3, it should be 100MB.
const DISCORD_FILE_LIMIT = 8000000;

export default {
	async email(message, env, ctx) {
		let forwardData = await env.mailbox.get(message.to);
		if (!forwardData) forwardData = await env.mailbox.get("default");
		if (!forwardData) message.setReject("Server configuration error");

		const forwardJSON = JSON.parse(forwardData);

		if (forwardJSON) {
			await message.forward(forwardJSON.forward);
		} else {
			throw "Server configuration error";
		}
		const rawEmail = new Response(message.raw);
		const arrayBuffer = await rawEmail.arrayBuffer();
		const parser = new PostalMime.default();
		const email = await parser.parse(arrayBuffer);
		let emailText = email.text;
		if (!emailText) {
			// If there is no text, try to get the text from the html
			emailText = convert(email.html);
		}
		// The overall limit is 6000 characters, and we limit the embed body to 4096 characters, so the rest has ~1900 characters to work with
		const embedBody = JSON.stringify({
			embeds: [
				{
					title: this.trimToLimit(email.subject, 256), // Limit is 256
					description:
						emailText.length > DISCORD_EMBED_LIMIT
							? `${emailText.substring(
									0,
									DISCORD_EMBED_LIMIT - 12,
								)}...(TRIMMED)`
							: emailText,
					author: {
						name: `${this.trimToLimit(email.from.name, 100)}${email.from.name.length > 64 ? "\n" : " "}<${this.trimToLimit(email.from.address, 100)}>`, // Limit of 256 characters, but we will be a bit careful
					},
					footer: {
						text: `${this.trimToLimit(message.to, 100)}으로 도착한 메일입니다`, // Limit of 2048 characters, but we will be careful
					},
				},
			],
		});
		const formData = new FormData();
		formData.append("payload_json", embedBody);
		if (emailText.length > DISCORD_EMBED_LIMIT) {
			const newTextBlob = new Blob([emailText], {
				type: "text/plain",
			});
			// If the text is too big, we need truncate the blob.
			if (newTextBlob.size < DISCORD_FILE_LIMIT) {
				formData.append("files[0]", newTextBlob, "email.txt");
			} else {
				formData.append(
					"files[0]",
					newTextBlob.slice(0, DISCORD_FILE_LIMIT, "text/plain"),
					"email-trimmed.txt",
				);
			}
		}
		const discordResponse = await fetch(forwardJSON.webhook, {
			method: "POST",
			body: formData,
		});
		if (discordResponse.ok === false) {
			console.log(
				`Discord Webhook Failed: Discord Response: ${discordResponse.status} ${discordResponse.statusText} -> ${await discordResponse.json()} `,
			);
		}
		// You probably will want to forward the mail anyway to an address, in case discord is down,
		// Or you could make it fail if the webhook fails, causing the sending mail server to error out.
		// Or you could do something more complex with adding it to a Queue and retrying sending to Discord, etc
		// For now, I don't really care about those conditions
	},
	trimToLimit(input, limit) {
		return input.length > limit
			? `${input.substring(0, limit - 12)}...(TRIMMED)`
			: input;
	},
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		if (!env.POLICY_AUD) {
			return new Response("Hello world!", {
				status: 200,
				headers: { "Content-Type": "text/plain", d_s: "1" },
			});
		}
		const token = request.headers.get("cf-access-jwt-assertion");

		if (url.pathname === "/api/new" && request.method === "PUT") {
			const authResult = await this.authToken(token, env);
			if (authResult === false) {
				return new Response(`Invalid token`, {
					status: 403,
					headers: { "Content-Type": "text/plain", d_s: "2" },
				});
			}

			let body;
			try {
				body = await request.json();
			} catch {
				return new Response(`Bad request`, {
					status: 400,
					headers: { "Content-Type": "text/plain", d_s: "3" },
				});
			}

			if (!body.webhook || !body.income || !body.forward) {
				return new Response(`Bad request`, {
					status: 400,
					headers: { "Content-Type": "text/plain", d_s: "4" },
				});
			}

			await env.mailbox.put(
				body.income,
				JSON.stringify({
					webhook: body.webhook,
					forward: body.forward,
				}),
			);

			return new Response("OPERATION_SUCCESS", {
				status: 200,
				headers: { "Content-Type": "text/plain", d_s: "-1" },
			});
		}
		return new Response("Hello world!", {
			status: 200,
			headers: { "Content-Type": "text/plain", d_s: "0" },
		});
	},
	async authToken(token, env) {
		if (!token) {
			return new Response("Hello world!", {
				status: 200,
				headers: { "Content-Type": "text/plain", d_s: "1" },
			});
		}

		try {
			const JWKS = createRemoteJWKSet(
				new URL(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`),
			);
			const { payload } = await jwtVerify(token, JWKS, {
				issuer: env.TEAM_DOMAIN,
				audience: env.POLICY_AUD,
			});
			return true;
		} catch (err) {
			console.error(err);
			return false;
		}
	},
};
