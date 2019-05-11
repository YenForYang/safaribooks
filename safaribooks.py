#!/usr/bin/python3
# coding - utf-8
import sys
from argparse import SUPPRESS, ArgumentParser
from json import load, dump
from logging import Formatter, getLogger, INFO, FileHandler
from multiprocessing import Process, Queue, Value
from os import path, makedirs, remove, walk
from random import random
from shutil import move, make_archive, get_terminal_size
from tempfile import TemporaryDirectory
from urllib.parse import urljoin, urlsplit, urlparse

import requests
from lxml import html, etree

PATH = path.dirname(path.realpath(__file__))
COOKIES_FILE = path.join(PATH, "cookies.json")
STORAGE_PATH = "/mnt/EBOOKS_SAFARI"  # rclone mount

SAFARI_BASE_HOST = "learning.oreilly.com"
SAFARI_BASE_URL = f"https://{SAFARI_BASE_HOST}"


class Display:
	BASE_FORMAT = Formatter(fmt="[%(asctime)s] %(message)s", datefmt="%d/%b/%Y %H:%M:%S")

	# SH_DEFAULT = "\033[0m" if "win" not in sys.platform else ""  # TODO: colors for Windows
	# SH_YELLOW = "\033[33m" if "win" not in sys.platform else ""
	# SH_BG_RED = "\033[41m" if "win" not in sys.platform else ""
	# SH_BG_YELLOW = "\033[43m" if "win" not in sys.platform else ""

	SH_DEFAULT,SH_YELLOW,SH_BG_RED,SH_BG_YELLOW = (
		"\033[0m","\033[33m","\033[41m","\033[43m"
	) if "win" not in sys.platform else ("","","","")

	def __init__(self, log_file):
		self.log_file = path.join(PATH, log_file)

		self.logger = getLogger("SafariBooks")
		self.logger.setLevel(INFO)
		logs_handler = FileHandler(filename=self.log_file)
		logs_handler.setFormatter(self.BASE_FORMAT)
		logs_handler.setLevel(INFO)
		self.logger.addHandler(logs_handler)

		self.columns, _ = get_terminal_size()

		self.logger.info("** SafariBooks **")

		self.book_ad_info = False
		self.css_ad_info = Value("i", 0)
		self.images_ad_info = Value("i", 0)
		self.last_request = (None,)
		self.in_error = False

		self.state_status = Value("i", 0)
		sys.excepthook = self.unhandled_exception

	def unregister(self):
		self.logger.handlers[0].close()
		sys.excepthook = sys.__excepthook__

	def log(self, message):
		self.logger.info(str(message))  # TODO: "utf-8", "replace"

	def out(self, put):
		sys.stdout.write(f'\r{" " * self.columns}\r{str(put)}\n')  # TODO: "utf-8", "replace"

	def info(self, message, state=False):
		self.log(message)
		output = (
			f"{self.SH_YELLOW}[*]{self.SH_DEFAULT} {message}" if not state
				else f"{self.SH_BG_YELLOW}[-]{self.SH_DEFAULT} {message}"
		)
		self.out(output)

	def error(self, error):
		if not self.in_error:  self.in_error = True

		self.log(error)
		self.out(f"{self.SH_BG_RED}[#]{self.SH_DEFAULT} {error}")

	def exit(self, error):
		self.error(str(error))
		self.out(
			f"{self.SH_YELLOW}[+]{self.SH_DEFAULT} Remove all `<BOOK NAME>/OEBPS/*.xhtml` files & retry."
		)
		self.out(f"{self.SH_BG_RED}[!]{self.SH_DEFAULT} Aborting...")

		self.save_last_request()
		sys.exit(1)

	def unhandled_exception(self, _, o, tb):
		from traceback import format_tb
		self.log("".join(format_tb(tb)))
		self.exit(f"Unhandled Exception: {o} (type: {o.__class__.__name__})")

	def save_last_request(self):
		if any(self.last_request):
			self.log("Last request done:\n\tURL: {0}\n\tDATA: {1}\n\tOTHERS: {2}\n\n\t{3}\n{4}\n\n{5}\n"
					 .format(*self.last_request))

	# def intro(self):
	# 	output = self.SH_YELLOW + """
	# 	      ____     ___         _
	# 	     / __/__ _/ _/__ _____(_)
	# 	    _\ \/ _ `/ _/ _ `/ __/ /
	# 	   /___/\_,_/_/ \_,_/_/ /_/
	# 	     / _ )___  ___  / /__ ___
	# 	    / _  / _ \/ _ \/  '_/(_-<
	# 	   /____/\___/\___/_/\_\/___/
	# 	""" + self.SH_DEFAULT
	# 	       output += "\n" + "~" * (self.columns // 2)
	# 	output = ""
	# 	self.out(output)

	def parse_description(self, desc):
		try:
			return html.fromstring(desc).text_content()
		except (html.etree.ParseError, html.etree.ParserError) as e:
			self.log(f"Error parsing description: {e}")
			return "n/d"

	def book_info(self, info):
		description = self.parse_description(info["description"]).replace("\n", " ")
		for t in [
			("Title", info["title"]), ("Authors", ", ".join(aut["name"] for aut in info["authors"])),
			("Identifier", info["identifier"]), ("ISBN", info["isbn"]),
			("Publishers", ", ".join(pub["name"] for pub in info["publishers"])),
			("Rights", info["rights"]),
			("Description", f"{description[:500]}..." if len(description) >= 500 else description),
			("Release Date", info["issued"]),
			("URL", info["web_url"])
		]:
			self.info(f"{self.SH_YELLOW}{t[0]}{self.SH_DEFAULT}: {t[1]}", True)

	def state(self, origin, done):
		progress = int(done * 100 / origin)
		bar = int(progress * (self.columns - 11) / 100)
		if self.state_status.value < progress:
			self.state_status.value = progress
			sys.stdout.write(
				f'\r    {self.SH_BG_YELLOW}[{("#" * bar).ljust(self.columns - 11, "-")}]'
				f'{self.SH_DEFAULT}{progress:>4}%{chr(10) if progress == 100 else ""}'
			)

	def done(self, epub_file):
		self.info(f"Done: {epub_file}\n\n"
				  f"Github: lorenzodifuccia/safaribooks\n\n{self.SH_BG_RED}[!]{self.SH_DEFAULT}")


def api_error(response):
	if "detail" in response and "Not found" in response["detail"]:
		return f"API: book not found.\n    Find the book identifier in the URL:\n    `{SAFARI_BASE_URL}/library/view/book-name/XXXXXXXXXXXXX/`"

	else:
		remove(COOKIES_FILE)
		return f"API: Out-of-Session ({response['detail']}).\n" if "detail" in response\
			else f"{Display.SH_YELLOW}[+]{Display.SH_DEFAULT} Use the `--cred` option to auth login to SafariBooksOnline."

	return message

class WinQueue(list):  # TODO: error while use `process` in Windows: can't pickle _thread.RLock objects
	def put(self, el):
		self.append(el)
	def qsize(self):
		return self.__len__()


class SafariBooks:
	LOGIN_URL = f"{SAFARI_BASE_URL}/accounts/login/"
	# API_TEMPLATE = SAFARI_BASE_URL + "/api/v1/book/{0}/"

	HEADERS = {
		"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"accept-encoding": "gzip,deflate",
		# "accept-language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
		"accept-language": "*",
		"cache-control": "no-cache",
		"cookie": "",
		"pragma": "no-cache",
		"origin": SAFARI_BASE_URL,
		"referer": LOGIN_URL,
		# "upgrade-insecure-requests": "1",
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
					  "Chrome/60.0.3112.113 Safari/537.36"
	}

	# BASE_01_HTML = '<!DOCTYPE html>\n' \
	# 			   '<html lang="en" xml:lang="en" xmlns="http://www.w3.org/1999/xhtml"' \
	# 			   ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	# 			   ' xsi:schemaLocation="http://www.w3.org/2002/06/xhtml2/' \
	# 			   ' http://www.w3.org/MarkUp/SCHEMA/xhtml2.xsd"' \
	# 			   ' xmlns:epub="http://www.idpf.org/2007/ops">\n' \
	# 			   '<head>\n' \
	# 			   '{0}\n' \
	# 			   '<style type="text/css">' \
	# 			   'body{{margin:1em;}}' \
	# 			   '#sbo-rt-content *{{text-indent:0pt!important;}}#sbo-rt-content .bq{{margin-right:1em!important;}}'

	# KINDLE_HTML =("body{{background-color:transparent!important;}}"
	# 			  "#sbo-rt-content *{{word-wrap:break-word!important;"
	# 			  "word-break:break-word!important;}}#sbo-rt-content table,#sbo-rt-content pre"
	# 			  "{{overflow-x:unset!important;overflow:unset!important;"
	# 			  "overflow-y:unset!important;white-space:pre-wrap!important;}}"
	# )
	# BASE_02_HTML = "</style>" \
	# 			   "</head>\n" \
	# 			   "<body>{1}</body>\n</html>"

	# Format: ID, Title, Authors, Description, Subjects, Publisher, Rights, Date, CoverId, MANIFEST, SPINE, CoverUrl
	# CONTENT_OPF = '<package xmlns="http://www.idpf.org/2007/opf" unique-identifier="bookid" version="2.0">\n' \
	# 			  '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:opf="http://www.idpf.org/2007/opf">\n' \
	# 			  '<dc:title>{1}</dc:title>\n' \
	# 			  '{2}\n' \
	# 			  '<dc:description>{3}</dc:description>\n' \
	# 			  '{4}' \
	# 			  '<dc:publisher>{5}</dc:publisher>\n' \
	# 			  '<dc:rights>{6}</dc:rights>\n' \
	# 			  '<dc:language>en-US</dc:language>\n' \
	# 			  '<dc:date>{7}</dc:date>\n' \
	# 			  '<dc:identifier id="bookid">{0}</dc:identifier>\n' \
	# 			  '<meta name="cover" content="{8}"/>\n' \
	# 			  '</metadata>\n' \
	# 			  '<manifest>\n' \
	# 			  '<item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml" />\n' \
	# 			  '{9}\n' \
	# 			  '</manifest>\n' \
	# 			  '<spine toc="ncx">\n{10}</spine>\n' \
	# 			  '<guide><reference href="{11}" title="Cover" type="cover" /></guide>\n' \
	# 			  '</package>'

	# Format: ID, Depth, Title, Author, NAVMAP
	# TOC_NCX = '<?xml version="1.0" encoding="utf-8"?>\n' \
	# 		  '<!DOCTYPE ncx PUBLIC "-//NISO//DTD ncx 2005-1//EN"' \
	# 		  ' "http://www.daisy.org/z3986/2005/ncx-2005-1.dtd">\n' \
	# 		  '<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">\n' \
	# 		  '<head>\n' \
	# 		  '<meta content="ID:ISBN:{0}" name="dtb:uid"/>\n' \
	# 		  '<meta content="{1}" name="dtb:depth"/>\n' \
	# 		  '<meta content="0" name="dtb:totalPageCount"/>\n' \
	# 		  '<meta content="0" name="dtb:maxPageNumber"/>\n' \
	# 		  '</head>\n' \
	# 		  '<docTitle><text>{2}</text></docTitle>\n' \
	# 		  '<docAuthor><text>{3}</text></docAuthor>\n' \
	# 		  '<navMap>{4}</navMap>\n' \
	# 		  '</ncx>'

	def __init__(self, args):
		self.args = args
		self.display = Display(f"info_{html_escape(args.bookid)}.log")
		# self.display.intro()

		self.cookies = {}

		if not args.cred:
			if not path.isfile(COOKIES_FILE):
				self.display.exit("Login: unable to find cookies file.\n\tTry the --cred option to login.")
			self.cookies = load(open(COOKIES_FILE))
		else:
			self.display.info("Logging in...", state=True)
			self.do_login(*args.cred)
			if not args.no_cookies:
				dump(self.cookies, open(COOKIES_FILE, "w"))

		self.book_id = args.bookid
		self.api_url = f"{SAFARI_BASE_URL}/api/v1/book/{self.book_id}/"

		self.display.info("Getting book info...")
		self.book_info = self.get_book_info()
		self.display.book_info(self.book_info)

		self.display.info("Getting book chapters...")
		self.book_chapters = self.get_book_chapters()

		self.chapters_queue = self.book_chapters[:]

		if len(self.book_chapters) > sys.getrecursionlimit():
			sys.setrecursionlimit(len(self.book_chapters))

		self.book_title = self.book_info["title"]
		self.base_url = self.book_info["web_url"]

		self.clean_book_title = f'{"".join(escape_dirname(self.book_title).split(",")[:2])} ({self.book_id})'
		with TemporaryDirectory() as self.TMP_BOOK_PATH:
			self.BOOK_PATH = path.join(STORAGE_PATH, self.clean_book_title)
			makedirs(self.BOOK_PATH, exist_ok=True)
			self.css_path, self.images_path = "", ""
			self.create_dirs()
			self.display.info(f"Temporary output directory:\n    {self.TMP_BOOK_PATH}")

			self.chapter_title,self.filename = "",""
			self.css,self.images = [],[]

			self.display.info(f"Getting book contents... ({len(self.book_chapters)} chapters)", state=True)

			self.cover = False
			self.get()
			if not self.cover:
				self.cover = self.get_default_cover()
				cover_html = self.parse_html(
					html.fromstring(f'<div id="sbo-rt-content"><img src="Images/{self.cover}"></div>'),
					True
				)

				self.book_chapters[:0] = [{  # prepend
					"filename": "default_cover.xhtml",
					"title": "Cover"
				}]

				self.filename = self.book_chapters[0]["filename"]
				self.save_page_html(cover_html)

			self.css_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
			self.display.info(f"Downloading book CSSs... ({len(self.css)} files)", state=True)
			self.collect_css()
			self.images_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
			self.display.info(f"Downloading book images... ({len(self.images)} files)", state=True)
			self.collect_images()

			self.display.info("Creating EPUB...", state=True)
			self.create_epub()
			if not args.no_cookies:
				dump(self.cookies, open(COOKIES_FILE, "w"))

			self.display.done(path.join(self.TMP_BOOK_PATH, f"{self.book_id}.epub"))
			self.display.unregister()

		if not self.display.in_error and not args.log:
			remove(self.display.log_file)

		sys.exit(0)

	def return_cookies(self):
		return " ".join([f"{k}={v};" for k, v in self.cookies.items()])

	def return_headers(self, url):
		self.HEADERS["cookie"] = self.return_cookies() if SAFARI_BASE_HOST in urlsplit(url).netloc else ""
		return self.HEADERS

	def update_cookies(self, jar):
		for cookie in jar:
			self.cookies.update({cookie.name: cookie.value})

	def requests_provider(self, url, post=False, data=None, update_cookies=True, **kwargs):
		try:
			response = getattr(requests, "post" if post else "get")(
				url,
				headers=self.return_headers(url),
				data=data,
				**kwargs
			)

			self.display.last_request = (
				url, data, kwargs, response.status_code, "\n".join(
					["\t{}: {}".format(*h) for h in response.headers.items()]
				), response.text
			)
		except (requests.ConnectionError, requests.ConnectTimeout, requests.RequestException) as request_exception:
			self.display.error(str(request_exception))
			return 0

		if update_cookies: self.update_cookies(response.cookies)
		return response

	def do_login(self, email, password):
		resp = self.requests_provider(self.LOGIN_URL)
		if resp == 0:
			self.display.exit("Login: unable to reach SafariBooksOnline. Try again...")

		csrf = []
		try:
			csrf = html.fromstring(resp.text).xpath("//input[@name='csrfmiddlewaretoken'][@value]")

		except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
			self.display.error(parsing_error)
			self.display.exit("Login: error parsing SafariBooksOnline homepage.")

		if not len(csrf):
			self.display.exit("Login: no CSRF Token found. Unable to login. Try again...")

		csrf = csrf[0].attrib["value"]
		resp = self.requests_provider(
			self.LOGIN_URL,
			post=True,
			data=(
				("csrfmiddlewaretoken", csrf),
				("email", email), ("password1", password),
				("login", "Sign In"), ("next", "")
			),
			allow_redirects=False
		)

		if resp == 0:
			self.display.exit("Login: Failed auth to Safari Books Online.\n    Try again...")

		if resp.status_code != 302:
			try:
				error_page = html.fromstring(resp.text)
				errors_message = error_page.xpath("//ul[@class='errorlist']//li/text()")
				recaptcha = error_page.xpath("//div[@class='g-recaptcha']")
				messages = \
					( [f"    `{error}`" for error in errors_message
					    if "password" in error or "email" in error
					   ]
					     if len(errors_message) else []
					) + (
					  ["    `ReCaptcha required (wait or do logout from the website).`"] if len(recaptcha) else []
					)
				self.display.exit(
					f"Login: Failed auth login to Safari Books Online.\n{self.display.SH_YELLOW}[*]{self.display.SH_DEFAULT}"
					f" Details:\n{chr(10).join(messages if len(messages) else '    Unexpected error!')}"
				)
			except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
				self.display.error(parsing_error)
				self.display.exit(
					"Login failed. Error in parsing the login details of SafariBooksOnline. Try again..."
				)


	def get_book_info(self):
		resp = self.requests_provider(self.api_url)
		if resp.status_code != 200: self.display.exit("API: unable to get book info.")

		resp = resp.json()
		if not isinstance(resp, dict) or len(resp.keys()) == 1:
			self.display.exit(api_error(resp))

		if "last_chapter_read" in resp:  del resp["last_chapter_read"]

		return resp



	def get_book_chapters(self, page=1):
		resp = self.requests_provider(urljoin(self.api_url, f"chapter/?page={page}"))
		if resp.status_code != 200:  self.display.exit("API: unable to get book chapters.")

		resp = resp.json()
		if not isinstance(resp, dict) or len(resp.keys()) == 1:
			self.display.exit(api_error(resp))

		if "results" not in resp or not len(resp["results"]):
			self.display.exit("API: unable to get book chapters.")

		if resp["count"] > sys.getrecursionlimit():    sys.setrecursionlimit(resp["count"])

		result = [c  for c in resp["results"]
		               if "cover" in c["filename"] or "cover" in c["title"]
		]

		for c in result:  del resp["results"][resp["results"].index(c)]

		return result + resp["results"] + self.get_book_chapters(page + 1) if resp["next"]\
			else result + resp["results"]

	def get_default_cover(self):
		resp = self.requests_provider(self.book_info["cover"], update_cookies=False)
		if resp.status_code != 200:
			self.display.error(f"Error getting cover: {self.book_info['cover']}")
			return False

		file_ext = resp.headers["Content-Type"].rsplit("/",1)[-1]
		with open(path.join(self.images_path, f"default_cover.{file_ext}"), 'wb') as i:
			i.write(resp.content)
		return f"default_cover.{file_ext}"


	def get_html(self, url):
		resp = self.requests_provider(url)
		if resp.status_code != 200:
			self.display.exit(
				f"Crawler: error getting page: {self.filename} ({self.chapter_title})\n    From: {url}"
			)

		try: return html.fromstring(resp.text, base_url=SAFARI_BASE_URL)

		except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
			self.display.error(parsing_error)
			self.display.exit(
				f"Crawler: error parsing page: {self.filename} ({self.chapter_title})\n    From: {url}"
			)


	def link_replace(self, link):
		if link:
			if not url_is_absolute(link):
				if "cover" in link or "images" in link or "graphics" in link or \
						link[-3:] in ["jpg", "peg", "png", "gif"]:
					link = urljoin(self.base_url, link)
					if link not in self.images:
						self.images.append(link)
						self.display.log(f"Crawler: found a new image at {link}")

					return "Images/" + link.rsplit("/",1)[-1]

				return html_to_xhtml(link)
			else:
				if self.book_id in link:
					return self.link_replace(link.split(self.book_id)[-1])

		return link

	def parse_html(self, root, first_page=False):
		if random() > 0.8:
			if len(root.xpath("//div[@class='controls']/a/text()")):
				self.display.exit(api_error(" "))

		book_content = root.xpath("//div[@id='sbo-rt-content']")
		if not len(book_content):
			self.display.exit(
				f"Parser: book content's corrupt or absent: {self.filename} ({self.chapter_title})"
			)

		page_css = ""
		stylesheet_links = root.xpath("//link[@rel='stylesheet']")
		if len(stylesheet_links):
			stylesheet_count = 0
			for s in stylesheet_links:
				css_url = urljoin("https:", s.attrib["href"]) if s.attrib["href"][:2] == "//" \
					else urljoin(self.base_url, s.attrib["href"])

				if css_url not in self.css:
					self.css.append(css_url)
					self.display.log(f"Crawler: found a new CSS at {css_url}")

				page_css += f'<link href="Styles/Style{stylesheet_count:0>2}.css" rel="stylesheet" type="text/css"/>\n'
				stylesheet_count += 1

		stylesheets = root.xpath("//style")
		if len(stylesheets):
			for css in stylesheets:
				if "data-template" in css.attrib and len(css.attrib["data-template"]):
					css.text = css.attrib["data-template"]
					del css.attrib["data-template"]

				try:
					page_css += html.tostring(css, method="xml", encoding='unicode') + "\n"

				except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
					self.display.error(parsing_error)
					self.display.exit(
						f"Parser: error parsing 1 CSS found in page: {self.filename} ({self.chapter_title})"
					)

		# TODO: add all not covered tag for `link_replace` function
		svg_image_tags = root.xpath("//image")

		if len(svg_image_tags):
			for img in svg_image_tags:
				image_attr_href = [x for x in img.attrib.keys() if "href" in x]
				if len(image_attr_href):
					svg_url = img.attrib.get(image_attr_href[0])
					svg_root = img.getparent().getparent()
					new_img = svg_root.makeelement("img")
					new_img.attrib.update({"src": svg_url})
					svg_root.remove(img.getparent())
					svg_root.append(new_img)

		book_content = book_content[0]
		book_content.rewrite_links(self.link_replace)

		try:
			if first_page:
				is_cover = get_cover(book_content)
				if is_cover is not None:
					page_css = ("<style>"
								"body{display:table;position:absolute;margin:0!important;height:100%;width:100%;}"
								"#Cover{display:table-cell;vertical-align:middle;text-align:center;}"
								"img{height:90vh;margin-left:auto;margin-right:auto;}"
								"</style>"
					)
					cover_html = html.fromstring('<div id="Cover"></div>')
					cover_div = cover_html.xpath("//div")[0]
					cover_img = cover_div.makeelement("img")
					cover_img.attrib.update({"src": is_cover.attrib["src"]})
					cover_div.append(cover_img)
					book_content = cover_html

					self.cover = is_cover.attrib["src"]

			return page_css, html.tostring(book_content, method="xml", encoding='unicode')

		except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
			self.display.error(parsing_error)
			self.display.exit(
				f"Parser: error parsing HTML of page: {self.filename} ({self.chapter_title})"
			)

	def create_dirs(self):
		if path.isdir(self.TMP_BOOK_PATH):
			self.display.log(f"Book directory already exists: {self.TMP_BOOK_PATH}")
		else:
			makedirs(self.TMP_BOOK_PATH)

		oebps = path.join(self.TMP_BOOK_PATH, "OEBPS")
		if not path.isdir(oebps):
			self.display.book_ad_info = True
			makedirs(oebps)

		self.css_path = path.join(oebps, "Styles")
		if path.isdir(self.css_path):
			self.display.log(f"CSSs directory already exists: {self.css_path}")
		else:
			makedirs(self.css_path)
			self.display.css_ad_info.value = 1

		self.images_path = path.join(oebps, "Images")
		if path.isdir(self.images_path):
			self.display.log(f"Images directory already exists: {self.images_path}")
		else:
			makedirs(self.images_path)
			self.display.images_ad_info.value = 1

	def save_page_html(self, contents):
		self.filename = html_to_xhtml(self.filename)
		with open(path.join(self.TMP_BOOK_PATH, "OEBPS", self.filename), "wb") as OEBPS:
			OEBPS.write(
				('<!DOCTYPE html>\n<html lang="en" xml:lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.w3.org/2002/06/xhtml2/ http://www.w3.org/MarkUp/SCHEMA/xhtml2.xsd" xmlns:epub="http://www.idpf.org/2007/ops">\n'
				 f'<head>\n{contents[0]}\n<style type="text/css">body{{margin:1em;}}#sbo-rt-content *{{text-indent:0pt!important;}}#sbo-rt-content .bq{{margin-right:1em!important;}}'
				 f'{"body{{background-color:transparent!important;}}#sbo-rt-content *{{word-wrap:break-word!important;word-break:break-word!important;}}#sbo-rt-content table,#sbo-rt-content pre{{overflow-x:unset!important;overflow:unset!important;overflow-y:unset!important;white-space:pre-wrap!important;}}" if not self.args.no_kindle else ""}'
				 f"</style></head>\n<body>{contents[1]}</body>\n</html>"
				).encode("utf-8", 'xmlcharrefreplace')
			)
		self.display.log(f"Created: {self.filename}")

	def get(self):
		len_books = len(self.book_chapters)

		for _ in range(len_books):
			if not len(self.chapters_queue): return

			first_page = len_books == len(self.chapters_queue)

			next_chapter = self.chapters_queue.pop(0)
			self.chapter_title = next_chapter["title"]
			self.filename = next_chapter["filename"]

			if path.isfile(path.join(self.TMP_BOOK_PATH, "OEBPS", html_to_xhtml(self.filename))):
				if not self.display.book_ad_info and \
						next_chapter not in self.book_chapters[:self.book_chapters.index(next_chapter)]:
					self.display.info(
						f"File `{html_to_xhtml(self.filename)}` already exists.\n    To redownload all of the book"
						f"{' (especially since the `--no-kindle` option was selected)' if self.args.no_kindle else ''},\n"
						f"    delete the `<BOOK NAME>/OEBPS/*.xhtml` files & retry."
					)
					self.display.book_ad_info = 2
			else:
				self.save_page_html(self.parse_html(self.get_html(next_chapter["web_url"]), first_page))

			self.display.state(len_books, len_books - len(self.chapters_queue))

	def _thread_download_css(self, url):
		css_file = path.join(self.css_path, f"Style{self.css.index(url):0>2}.css")
		if path.isfile(css_file):
			if not self.display.css_ad_info.value and url not in self.css[:self.css.index(url)]:
				self.display.info(
					f"File `{css_file}` already exists.\n"
					f"    To redownload all the CSSs,\n"
					f"delete the `<BOOK OOK NAME>/OEBPS/*.xhtml` & `<BOOK NAME>/OEBPS/Styles/*` files & retry.")
				self.display.css_ad_info.value = 1
		else:
			resp = self.requests_provider(url, update_cookies=False)

			if resp.status_code == 200:
				with open(css_file, 'wb') as s:
					s.write(resp.content)
			else:
				self.display.error(f"Error getting this CSS: {css_file}\n    From: {url}")

		self.css_done_queue.put(1)
		self.display.state(len(self.css), self.css_done_queue.qsize())

	def _thread_download_images(self, url):
		image_name = url.rsplit("/",1)[-1]
		image_path = path.join(self.images_path, image_name)
		if path.isfile(image_path):
			if not self.display.images_ad_info.value and url not in self.images[:self.images.index(url)]:
				self.display.info(
					f"File `{image_name}` already exists.\n"
					f"    To redownload all images,\ndelete the `<BOOK OOK NAME>/OEBPS/*.xhtml` & `<BOOK NAME>/OEBPS/Images/*` files & retry.")
				self.display.images_ad_info.value = 1
		else:
			resp = self.requests_provider(urljoin(SAFARI_BASE_URL, url), update_cookies=False)
			if resp.status_code == 200:
				with open(image_path, 'wb') as img:  img.write(resp.content)
			else:
				self.display.error(f"Error getting this image: {image_name}\n    From: {url}")

		self.images_done_queue.put(1)
		self.display.state(len(self.images), self.images_done_queue.qsize())

	def _start_multiprocessing(self, operation, full_queue):
		if len(full_queue) > 5:
			for i in range(0, len(full_queue), 5):
				self._start_multiprocessing(operation, full_queue[i:i + 5])
		else:
			process_queue = [Process(target=operation, args=(arg,)) for arg in full_queue]
			for proc in process_queue: proc.start()
			for proc in process_queue: proc.join()

	def collect_css(self):
		self.display.state_status.value = -1

		if "win" in sys.platform:
			# TODO
			for css_url in self.css:
				self._thread_download_css(css_url)
		else:
			self._start_multiprocessing(self._thread_download_css, self.css)

	def collect_images(self):
		if self.display.book_ad_info == 2:
			self.display.info("Book contents were partially downloaded.\n"
							  "    To ensure that all the images are downloaded,\n"
							  "    delete the `<BOOK NAME>/OEBPS/*.xhtml` files & restart the program.")
		self.display.state_status.value = -1

		if "win" in sys.platform:
			# TODO
			for image_url in self.images: self._thread_download_images(image_url)
		else:
			self._start_multiprocessing(self._thread_download_images, self.images)

	def create_content_opf(self):
		self.css = next(walk(self.css_path))[2]
		self.images = next(walk(self.images_path))[2]

		manifest,spine = [],[]

		for c in self.book_chapters:
			c["filename"] = html_to_xhtml(c["filename"])
			item_id = html_escape(c["filename"].rsplit(".", 1)[0])
			manifest.append(f'<item id="{item_id}" href="{c["filename"]}" media-type="application/xhtml+xml"/>')
			spine.append(f'<itemref idref="{item_id}"/>')

		for i in set(self.images):
			dot_split = i.rsplit(".",1)
			head = f'img_{html_escape(dot_split[0])}'
			manifest.append(
				f'<item id="{head}" href="Images/{i}" media-type="image/{"jpeg" if "jp" in dot_split[-1] else dot_split[-1]}"/>'
		)

		for i in range(len(self.css)):
			manifest.append(f'<item id="style_{i:0>2}" href="Styles/Style{i:0>2}.css" media-type="text/css"/>')

		authors = "\n".join(
			f'<dc:creator opf:file-as="{html_escape(aut["name"])}" opf:role="aut">{html_escape(aut["name"])}</dc:creator>'
				for aut in self.book_info["authors"]
		)

		subjects = "\n".join(
			f"<dc:subject>{html_escape(sub['name'])}</dc:subject>"
				for sub in self.book_info["subjects"]
		)

		return (
			f'<package xmlns="http://www.idpf.org/2007/opf" unique-identifier="bookid" version="2.0">\n<metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:opf="http://www.idpf.org/2007/opf">\n'
			f'<dc:title>{html_escape(self.book_title)}</dc:title>\n'
			f'{authors}\n'
			f'<dc:description>{html_escape(self.book_info["description"])}</dc:description>\n'
			f'{subjects}'
			f'<dc:publisher>{", ".join(html_escape(pub["name"]) for pub in self.book_info["publishers"])}</dc:publisher>\n'
			f'<dc:rights>{html_escape(self.book_info["rights"])}</dc:rights>\n'
			f'<dc:language>en-US</dc:language>\n<dc:date>{self.book_info["issued"]}</dc:date>\n'
			f'<dc:identifier id="bookid">{(self.book_info["isbn"] if self.book_info["isbn"] else self.book_id)}</dc:identifier>\n'
			f'<meta name="cover" content="{self.cover}"/>\n</metadata>\n<manifest>\n'
			f'<item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>\n{chr(10).join(manifest)}\n</manifest>\n'
			f'<spine toc="ncx">\n{chr(10).join(spine)}</spine>\n'
			f'<guide><reference href="{html_to_xhtml(self.book_chapters[0]["filename"])}" title="Cover" type="cover" /></guide>\n</package>'
		)

	def create_toc(self):
		response = self.requests_provider(urljoin(self.api_url, "toc/"))
		if response == 0:
			self.display.exit("API: unable to retrieve book chapters. "
							  "Rerun this program without deleting any files"
							  " to complete EPUB creation!")

		response = response.json()
		if not isinstance(response, list) and len(response.keys()) == 1:
			self.display.exit(
				f"{api_error(response)} Rerun this program without deleting any files to complete EPUB creation!"
			)

		navmap, _, max_depth = parse_toc(response)

		return (
			f'<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE ncx PUBLIC "-//NISO//DTD ncx 2005-1//EN" "http://www.daisy.org/z3986/2005/ncx-2005-1.dtd">\n'
			f'<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">\n<head>\n'
			f'<meta content="ID:ISBN:{self.book_info["isbn"] if self.book_info["isbn"] else self.book_id}" name="dtb:uid"/>\n'
			f'<meta content="{max_depth}" name="dtb:depth"/>\n<meta content="0" name="dtb:totalPageCount"/>\n'
			f'<meta content="0" name="dtb:maxPageNumber"/>\n</head>\n<docTitle><text>{self.book_title}</text></docTitle>\n'
			f'<docAuthor><text>{", ".join(aut["name"] for aut in self.book_info["authors"])}</text></docAuthor>\n'
			f'<navMap>{navmap}</navMap>\n</ncx>'
		)

	def create_epub(self):
		open(path.join(self.TMP_BOOK_PATH, "mimetype"), "w").write("application/epub+zip")
		meta_info = path.join(self.TMP_BOOK_PATH, "META-INF")
		# if path.isdir(meta_info):
		# 	self.display.log(f"META-INF directory already exists: {meta_info}")
		# else:
		# 	makedirs(meta_info)
		makedirs(meta_info)

		open(path.join(meta_info, "container.xml"), "wb").write(
			('<?xml version="1.0"?>'
			 '<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
			 '<rootfiles>'
			 '<rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml" />'
			 '</rootfiles>'
			 '</container>'
			).encode("utf-8","xmlcharrefreplace")
		)
		open(path.join(self.TMP_BOOK_PATH, "OEBPS", "content.opf"), "wb").write(
			self.create_content_opf().encode("utf-8","xmlcharrefreplace")
		)
		open(path.join(self.TMP_BOOK_PATH, "OEBPS", "toc.ncx"), "wb").write(
			self.create_toc().encode("utf-8","xmlcharrefreplace")
		)
		zip_file = path.join(self.TMP_BOOK_PATH, self.book_id)
		if path.isfile(f"{zip_file}.zip"):
			remove(f"{zip_file}.zip")

		make_archive(zip_file, 'zip', self.TMP_BOOK_PATH)
		move(f"{zip_file}.zip", f"{path.join(self.BOOK_PATH, self.book_id)}.epub")


# Functions

def parse_cred(cred):
	if ":" not in cred: return False

	sep = cred.index(":")
	new_cred = [cred[:sep].strip("'").strip('"'), ""]

	if "@" not in new_cred[0]: return False

	new_cred[1] = cred[sep + 1:]
	return new_cred


def parse_toc(l, c=0, mx=0):
	r = ""
	for cc in l:
		c += 1
		if int(cc["depth"]) > mx:  mx = int(cc["depth"])

		r += (f'<navPoint id="{cc["fragment"] if len(cc["fragment"]) else cc["id"]}" playOrder="{c}">'
			  f'<navLabel><text>{html_escape(cc["label"])}</text></navLabel>'
			  f'<content src="{html_to_xhtml(cc["href"]).rsplit("/", 1)[-1]}"/>'
		)

		if cc["children"]:
			sr, c, mx = parse_toc(cc["children"], c, mx)
			r += sr

		r += "</navPoint>\n"

	return r, c, mx


def escape_dirname(dirname, clean_space=False):
	if ":" in dirname:
		if dirname.index(":") > 15:
			dirname = dirname.split(":",1)[0]
		elif "win" in sys.platform:
			dirname = dirname.replace(":", ",")

	dirname = dirname.translate({ord(c): "_" for c in "~#%&*{}\\<>?/`'\"|+"})

	return dirname if not clean_space else dirname.replace(' ', '')


def get_cover(html_root):
	lowercase_ns = etree.FunctionNamespace(None)
	lowercase_ns["lower-case"] = lambda _, n: n[0].lower() if n and len(n) else ""

	images = html_root.xpath("//img[contains(lower-case(@id),'cover') or contains(lower-case(@class),'cover') or"
							 " contains(lower-case(@name),'cover') or contains(lower-case(@src),'cover') or"
							 " contains(lower-case(@alt),'cover')]")
	if len(images): return images[0]
	divs = html_root.xpath("//div[contains(lower-case(@id),'cover') or contains(lower-case(@class),'cover') or"
						   " contains(lower-case(@name),'cover') or contains(lower-case(@src),'cover')]//img")
	if len(divs):   return divs[0]
	a = html_root.xpath("//a[contains(lower-case(@id),'cover') or contains(lower-case(@class),'cover') or"
						" contains(lower-case(@name),'cover') or contains(lower-case(@src),'cover')]//img")
	if len(a):      return a[0]
	return None


def url_is_absolute(url):	return bool(urlparse(url).netloc)

def html_to_xhtml(f):
	return f[:-4] + "xhtml" if f.endswith(".html") else f


def html_escape(s, quote=True):
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;").replace('\'', "&#x27;")
    return s

# MAIN
if __name__ == "__main__":
	args = ArgumentParser(prog="safaribooks.py",
						  description="Download & generate an EPUB from a SafariBooksOnline book.",
						  add_help=False,
						  allow_abbrev=False)

	args.add_argument(
		"--cred", metavar="<EMAIL:PASS>", default=False,
		help='Credentials used to auth login.'
			 ' Ex. ` --cred "user@email.com:password" `.'
	)
	args.add_argument(
		"--no-cookies", dest="no_cookies", action='store_true',
		help="Disable saving session data to `cookies.json`."
	)
	args.add_argument(
		"--no-kindle", dest="no_kindle", action='store_true',
		help="Remove some CSS rules that block overflow on `table` & `pre` elements."
			 " Use if you're not going to export the EPUB to E-Readers like Amazon Kindle."
	)
	args.add_argument(
		"--preserve-log", dest="log", action='store_true', help="Always keep the `info_XXXXXXXXXXXXX.log` file"
																" (default = keep only on error)."
	)
	args.add_argument("--help", action="help", default=SUPPRESS, help='Show this help message.')
	args.add_argument(
		"bookid", metavar='<BOOK ID>',
		help="Numeric ID of the book to download. Find it in the URL (X-es):"
			 f" `{SAFARI_BASE_URL}/library/view/book-name/XXXXXXXXXXXXX/`"
	)

	args_parsed = args.parse_args()

	if args_parsed.cred:
		parsed_cred = parse_cred(args_parsed.cred)
		if not parsed_cred:  args.error(f"invalid credential: {args_parsed.cred}")
		args_parsed.cred = parsed_cred
	else:
		if args_parsed.no_cookies:
			args.error("invalid option: `--no-cookies` is valid only with the `--cred` option")

	SafariBooks(args_parsed)


