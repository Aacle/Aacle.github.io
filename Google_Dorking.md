# Google Dorking

# Finding Vulnerable Info Using Google Dorks — Ethical Hacking

> Google Dorking is a technique that hackers use to find information that may have been accidentally exposed to the internet.

![](https://miro.medium.com/max/1400/1*zA_nrmrKwrbQKOecCfUpkQ.jpeg)

# What is Google Dorking?

Advanced use of Google Search Operator is called **Google Dorking**. In simple terms, it is using **Google to run targeted search queries using specific keywords or commands**. Basically narrowing down the search to find what we are looking for.

Google Dorking uses some of google’s inherent abilities to find things on the internet that we can find via specific search strings. These can be **log files**, **error files**, **webcams** opened to the internet, and even internal pages or admin that allow us to get into a device. In some cases, you can also find **passwords in error logs. Sometimes **even the **administration config files** are exposed to the internet due to the server being incorrectly set up.

![](https://miro.medium.com/max/970/1*Y3XJ7jK5pwBKXAHj0SyEvQ.gif)

Google Dorking is done by Google Search Operators. A few of them are :

-   **site:<keyword>** — used to limit the search results to a particular site. For eg., to google for hacking-related blogs on my website [https://gourav-dhar.com](https://gourav-dhar.com/). I would write :

hacking site:gourav-dhar.com

-   **inurl:<keyword>** — used to specify which keyword should be present in the URL. For the above query if I want to add a filter saying the URL should contain the string `ethical` I can write it as

hacking site:gourav-dhar.com inurl:ethical

You will get the following result :

![](https://miro.medium.com/max/1400/1*89Xb2Yi5_oOyHZy848Ym5A.png)

-   **intext:<keyword>** — This filter will check for the parameters being present in the meta-information of the website(i.e. the information you see on the title and description of a google search).

-   **intitle:<keyword>** — Result will return only those pages having the `keyword` in their HTML title

-   **allintitle** **:<keyword>**— searches for all the specified terms in the title.

-   **allinurl** **:<keyword>** — searches for all terms in the url.

-   **filetype:<keyword>** — Looks for explicit document types. filetype:pdf will searches for pdf files in sites

-   **ext:<keyword>** — Like filetype. ext:pdf finds pdf extension.

-   **cache** **:<keyword>** — Used to see Google’s cached version of a site

And there are a few other Search Operators as well which can be found via Google Search. Let me show you some of the cool stuff you can do with it.

Let’s look at some of the cool things we can do with it.

## 1\. Checking logs for credentials

allintext:username filetype:log

![](https://miro.medium.com/max/1400/1*gDl2d8cszM2nbFXo1Q51HA.png)

We will get a list of log files that contain the text “username”. This can be useful (for hackers) if the log by mistake contains the user credentials. If you explore the results a little bit and apply filters, you will be able to find usernames or passwords for further exploitation.

## 2\. Webcamas are super safe right — — Naaaah!

Google —` intitle:”webcamxp 5"` and you will find a list of webcams you can dive right into.

![](https://miro.medium.com/max/1400/1*lbdWpUg3QO7kYQ9cULGesw.png)

Look at this, live preview of some random lab it seems. Does anyone happen to know which place this is 😆

![](https://miro.medium.com/max/1400/1*YjaXlqmXdZvdudoM1qotBQ.png)

A good point to start is the Google Hacking Database. [**https://www.exploit-db.com/google-hacking-database**](https://www.exploit-db.com/google-hacking-database). If you are not sure about the query strings and how to frame them. Go to this site and search for it. Several people have done it before so you can use their search queries. The Google Hacking Database or the Exploit Database looks like this and you can enter your queries on the top right.

![](https://miro.medium.com/max/1400/1*3Sw2QeNgh4glSlG26rZAag.png)

# Summarising Google Dorks

Doing whatever I did above is not illegal. We are fetching information that has already been made public. Hackers make use of google dorks to find information that might have accidentally been made public. However, using the information that has been presented to do something which can be troublesome for someone is crossing the line.
