###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_couchdb_dir_trav_vuln.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# CouchDB Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:couchdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105903");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12095 $");

  script_name("CouchDB Directory Traversal Vulnerability");

  script_bugtraq_id(57313);
  script_cve_id("CVE-2012-5641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57313");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81240");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jan/81");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-28 11:20:26 +0700 (Mon, 28 Apr 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_couchdb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 5984);
  script_mandatory_keys("couchdb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Directory traversal vulnerability on MobchiWeb/CouchDB resulting
  in information disclosure.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 1.0.4, 1.1.2, 1.2.1 or later.");
  script_tag(name:"insight", value:"On Windows systems there is a directory traversal vulnerability in the
  partition2 function in mochiweb_util.erl in MochiWeb before 2.4.0, as used in Apache
  CouchDB allows remote attackers to read arbitrary files via a ..\ (dot dot backslash)
  in the default URI.");
  script_tag(name:"affected", value:"CouchDB Version 1.0.3, 1.1.1, 1.2.0 on Windows");
  script_tag(name:"impact", value:"A remote attacker could retrieve in binary form any CouchDB database,
  including the _users or _replication databases, or any other file that the user account
  used to run CouchDB might have read access to on the local filesystem.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!port = get_app_port(cpe:CPE)) {
  exit(0);
}

if (vers = get_app_version(cpe:CPE, port:port)) {
  if (revcomp(a:vers, b:"1.0.4") < 0) {
    report = 'Installed version: ' + vers + '\nFixed version:     1.0.4';
  } else if ((revcomp(a:vers, b:"1.1.2") < 0) &&
             (revcomp(a:vers, b:"1.1.0") >= 0 )) {
    report = 'Installed version: ' + vers + '\nFixed version:     1.1.2';
  } else if (revcomp(a:vers, b:"1.2.0") == 0) {
    report = 'Installed version: ' + vers + '\nFixed version:     1.2.1';
  }
}

if (report) {
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
