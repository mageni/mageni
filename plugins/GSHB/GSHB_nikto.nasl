###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_nikto.nasl 13985 2019-03-05 07:23:54Z cfischer $
#
# Starts nikto with Option -Tuning x016bc and write to KB
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96044");
  script_version("$Revision: 13985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:23:54 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Starts nikto with Option -Tuning x016bc and write to KB");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "httpver.nasl", "logins.nasl",
                      "http_ids_evasion.nasl", "ids_evasion.nasl", "no404.nasl", "toolcheck.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_add_preference(name:"Force scan even without 404s", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This plugin uses nikto to find weak CGI scripts
  and other known issues regarding web server security. It starts with the option

  - Tuning x016bc

  and writes only OSVDB and CVE issues to the KB.

  Note: The plugin needs the 'nikto' or 'nikto.pl' binary found within the PATH of the user running the scanner and
  needs to be executable for this user. The existence of this binary is checked and reported separately
  within 'Availability of scanner helper tools' (OID: 1.3.6.1.4.1.25623.1.0.810000).");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");

nikto = get_kb_item("Tools/Present/nikto/bin");
if(!nikto || "nikto" >!< nikto || ! get_kb_item("Tools/Present/nikto")) {
  text  = 'Nikto could not be found in your system path.\n';
  text += 'The scanner was unable to execute Nikto and to perform the scan you requested.\n';
  test += 'Please make sure that Nikto is installed and that nikto.pl or nikto is available in the PATH variable defined for your environment.';
  log_message(port:0, proto:"IT-Grundschutz", data:text);
  set_kb_item(name:"GSHB/NIKTO", value:"error");
  exit(0);
}

user = get_kb_item("http/login");
pass = get_kb_item("http/login");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_http_port(default:80, ignore_unscanned:TRUE, ignore_broken:TRUE);
if(!get_port_state(port)) {
  set_kb_item(name:"GSHB/NIKTO", value:"error");
  log_message(port:0, proto:"IT-Grundschutz", data:"Can't open port " + port + " for Nikto test.");
  exit(0);
}

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
    log_message(port:0, proto:"IT-Grundschutz", data:text);
    set_kb_item(name:"GSHB/NIKTO", value:"error");
    exit(0);
  } else {
    text += 'You have requested to force this scan. Please be aware that Nikto is very likely to report false\n';
    text += 'positives under these circumstances. You need to check whether the issues reported by Nikto are\n';
    text += 'real threats or were caused by otherwise correct configuration on the target server.\n';
    log_message(port:0, proto:"IT-Grundschutz", data:text);
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
argv[i++] = "-T";
argv[i++] = "x016bc";

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
if(!r) {
  set_kb_item(name:"GSHB/NIKTO", value:"error");
  log_message(port:0, proto:"IT-Grundschutz", data:"Nikto has no result!");
  exit(0);
}

foreach l (split(r)) {
  l = ereg_replace(string:l, pattern:'^[ \t]+', replace:'');
  if("\+ OSVDB" >< l || l =~ "CVE-[0-9]+-[0-9]+")
    report += l;
}

if(!report)
  report = "none";

set_kb_item(name:"GSHB/NIKTO", value:report);