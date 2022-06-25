###############################################################################
# OpenVAS Vulnerability Test
#
# Apache CouchDB 'HTTP API' Privilege Escalation Vulnerability Aug18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813908");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-11769");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-09 17:11:15 +0530 (Thu, 09 Aug 2018)");
  script_name("Apache CouchDB 'HTTP API' Privilege Escalation Vulnerability Aug18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache CouchDB
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of administrator-supplied configuration settings via the HTTP
  API.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to escalate their privileges to that of the operating system's and
  remotely execute arbitrary code.");

  script_tag(name:"affected", value:"Apache CouchDB versions before 2.2.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache CouchDB version 2.2.0
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/1052ad7a1b32b9756df4f7860f5cb5a96b739f444117325a19a4bf75@%3Cdev.couchdb.apache.org%3E");
  script_xref(name:"URL", value:"http://couchdb.apache.org/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_couchdb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 5984);
  script_mandatory_keys("couchdb/installed", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!cPort = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:cPort, exit_no_version:TRUE)) exit(0);
cVer = infos['version'];
cPath = infos['location'];

if(version_is_less(version:cVer, test_version:"2.2.0"))
{
  report = report_fixed_ver(installed_version:cVer, fixed_version:"2.2.0", install_path:cPath);
  security_message(port:cPort, data:report);
  exit(0);
}
