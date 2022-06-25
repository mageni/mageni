###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_dos_9_17_lin.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Apache Struts Multiple Denial-of-Service Vulnerabilities (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107239");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-11 14:24:03 +0200 (Mon, 11 Sep 2017)");
  script_cve_id("CVE-2017-9793", "CVE-2017-9804");
  script_bugtraq_id(100611);

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts Multiple Denial-of-Service Vulnerabilities (Linux)");
  script_tag(name:"summary", value:"Apache Struts is prone to two denial-of-service vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a denial-of-service condition, denying service to legitimate users.");
  script_tag(name:"affected", value:"Apache Struts 2.3.7 through 2.3.33, and 2.5 through  2.5.12 are vulnerable");
  script_tag(name:"solution", value:"Updates are available. Apache Struts 2.3.x users should update to Apache Struts 2.3.34, Apache Struts 2.5.x users should update to Apache Struts 2.5.13.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100611");
  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-050.html");
  script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-051.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Denial of Service");

  script_dependencies("gb_apache_struts_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)) {
  exit(0);
}

if (version_in_range(version: Ver, test_version: "2.3.7", test_version2: "2.3.33")) {
  vuln = TRUE;
  fix = "2.3.34";
}
else if (version_in_range(version: Ver, test_version: "2.5", test_version2: "2.5.12")) {
  vuln = TRUE;
  fix = "2.5.13";
}

if (vuln) {
  report = report_fixed_ver(installed_version: Ver, fixed_version: fix);
  security_message(port: Port, data: report);
  exit(0);
}

exit(99);
