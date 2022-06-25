###############################################################################
# OpenVAS Vulnerability Test
# $Id: nikto.nasl 13985 2019-03-05 07:23:54Z cfischer $
#
# Nikto (NASL wrapper)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.14260");
  script_version("$Revision: 13985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:23:54 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nikto (NASL wrapper)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "logins.nasl", "no404.nasl",
                      "http_ids_evasion.nasl", "ids_evasion.nasl", "toolcheck.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Tools/Present/nikto");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Force scan even without 404s", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This plugin uses nikto to find weak CGI scripts and other known issues
  regarding web server security. See the preferences section for configuration options.

  Note: The plugin needs the 'nikto' or 'nikto.pl' binary found within the PATH of the user running the scanner and
  needs to be executable for this user. The existence of this binary is checked and reported separately
  within 'Availability of scanner helper tools' (OID: 1.3.6.1.4.1.25623.1.0.810000).");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");

if(!get_kb_item("Tools/Present/nikto"))
  exit(0);

nikto = get_kb_item("Tools/Present/nikto/bin");
if(!nikto || "nikto" >!< nikto)
  exit(0);

user = get_kb_item("http/login");
pass = get_kb_item("http/password");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_http_port(default:80, ignore_broken:TRUE); # Broken servers are checked later...
useragent = http_get_user_agent();
host = http_host_name(dont_add_port:TRUE);

# Nikto will generate many false positives if the web server is broken
no404 = http_get_no404_string(port:port, host:host);
if(no404) {
  text = 'The target server did not return 404 on requests for non-existent pages.\n';
  p = script_get_preference("Force scan even without 404s");
  if("no" >< p) {
    text += 'This scan has not been executed since Nikto is prone to reporting many false positives in this case.\n';
    text += 'If you wish to force this scan, you can enable it in the preferences of this script.\n';
    log_message(port:port, data:text);
    exit(0);
  } else {
    text += 'You have requested to force this scan. Please be aware that Nikto is very likely to report false\n';
    text += 'positives under these circumstances. You need to check whether the issues reported by Nikto are\n';
    text += 'real threats or were caused by otherwise correct configuration on the target server.\n';
    log_message(port:port, data:text);
  }
}

i = 0;
argv[i++] = nikto;

httpver = get_kb_item("http/" + port);
if(httpver == "11") {
  argv[i++] = "-vhost";
  argv[i++] = host;
}

# Use the no404 string found by no404.nasl
if(no404) {
  argv[i++] = "-404string";
  argv[i++] = no404;
}

if(useragent) {
  argv[i++] = "-useragent";
  argv[i++] = useragent;
}

# disable interactive mode, see http://attrition.org/pipermail/nikto-discuss/2010-September/000319.html
argv[i++] = "-ask";
argv[i++] = "no";

argv[i++] = "-h";
argv[i++] = get_host_ip();
argv[i++] = "-p";
argv[i++] = port;

encaps = get_port_transport(port);
if(encaps > ENCAPS_IP)
  argv[i++] = "-ssl";

if(ids && ids != "X") {
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if(user) {
  if(pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd:nikto, argv:argv, cd:TRUE);
if(!r)
  exit(0); # error

report = 'Here is the Nikto report:\n';
foreach l(split(r)) {
  l = ereg_replace(string:l, pattern:'^[ \t]+', replace:'');
  if(l[0] == '+' || l[0] == '-' || ! match(pattern:"ERROR*", string:l))
    report += l;
}

log_message(port:port, data:report);