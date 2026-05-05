# screenshots

For context, this folder contains three screenshots, which shows the entire conversation I had with the creator of the software.

As mentioned in [the video I made about it](https://www.youtube.com/watch?v=RHUWXXke9xA), the primary problem is as follows:

1. I introduced myself as someone just trying to be helpful. I provided a Claude Code security audit with the expectation that they would read through it and make considerations for updates later.
2. Within 18 minutes of me sending them that first message, [a new commit](https://github.com/TheGamingLemon256/Vryionics-VR-Optimization-Suite/pull/5/changes/6fe9f72532e752542c0e688728b90962ccfee13c) appeared on their PR. This commit included pretty much exactly the changes I outlined in my audit, and the commit even says, "Tighten everything the audit flagged that wasn't already addressed by the v0.2.9 architecture changes". (For context, this PR was open with 69 commits for at least 5 days prior, and it would've taken me at least 15 minutes to read through both of the documents I sent them).
3. Within the next 20 minutes, documentation was updated and that PR was merged as v0.2.9, which means the software was released and auto-updated to all users.
4. After that, they replied with their first message.
5. I expressed my concerns in my second message.
6. In their second and last message to me, they told me that I was misunderstanding, and that the changes they made were just one change they noticed.

They did not thank me for my inputs (in a context suggesting they used them directly). They did not tell me that they used my document. Within 1 hour, they went from having no idea who I was, to implementing some changes I suggested without peer-reviewing or deeply considering the changes.

This is a problem. They are the security hole. I could have just as easily crafted a convincing narrative that allowed me to convince Claude that my changes were better, and actually abused the security hole that I found. I could have had them push changes that were malicious, and I could have gained some level of access to people's computers.

That is the problem here. That is why I am making a stink about this.
