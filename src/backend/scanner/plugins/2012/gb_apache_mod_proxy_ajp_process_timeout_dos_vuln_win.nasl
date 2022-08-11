###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_proxy_ajp_process_timeout_dos_vuln_win.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Apache HTTP Server mod_proxy_ajp Process Timeout DoS Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802683");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2012-4557");
  script_bugtraq_id(56753);
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-06 18:00:42 +0530 (Thu, 06 Dec 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache HTTP Server mod_proxy_ajp Process Timeout DoS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed", "Host/runs_windows");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service condition via an expensive request.");
  script_tag(name:"affected", value:"Apache HTTP Server version 2.2.12 through 2.2.21");
  script_tag(name:"insight", value:"The flaw is due to an error in the mod_proxy_ajp module, which places a worker
  node into an error state upon detection of a long request-processing time.");
  script_tag(name:"summary", value:"The host is running Apache HTTP Server and is prone to denial
  of service vulnerability.");
  script_tag(name:"solution", value:"Apply patch or upgrade Apache HTTP Server 2.2.22 or later.
  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=871685");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html#2.2.22");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1227298");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1227298");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!httpPort = get_app_port(cpe:CPE))exit(0);
if(!httpVers = get_app_version(cpe:CPE, port:httpPort))exit(0);

if(httpVers && httpVers >!< "unknown" &&
   version_in_range(version:httpVers, test_version:"2.2.12", test_version2:"2.2.21"))
{
  security_message(port:httpPort);
  exit(0);
}
