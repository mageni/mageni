###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_mult_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# SAP NetWeaver Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:sap:netweaver';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106082");
  script_version("$Revision: 14181 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-23 09:47:56 +0700 (Mon, 23 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-1289", "CVE-2012-1290", "CVE-2012-1291", "CVE-2012-1292");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sap_netweaver_detect.nasl");
  script_mandatory_keys("sap_netweaver/installed");

  script_tag(name:"summary", value:"SAP NetWeaver is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SAP NetWeaver contains multiple vulnerabilities:
  Multiple directory traversal vulnerabilities in SAP NetWeaver 7.0 allow remote authenticated users to read
  arbitrary files via a .. (dot dot) in the logfilename parameter to b2b/admin/log.jsp, b2b/admin/log_view.jsp
  in the Internet Sales (crm.b2b) component, or ipc/admin/log.jsp or ipc/admin/log_view.jsp in the Application
  Administration (com.sap.ipc.webapp.ipc) component. (CVE-2012-1289)

  Cross-site scripting (XSS) vulnerability in b2b/auction/container.jsp in the Internet Sales (crm.b2b) module
  in SAP NetWeaver 7.0 allows remote attackers to inject arbitrary web script or HTML via the _loadPage parameter.
  (CVE-2012-1290)

  Unspecified vulnerability in the com.sap.aii.mdt.amt.web.AMTPageProcessor servlet in SAP NetWeaver 7.0 allows
  remote attackers to obtain sensitive information about the Adapter Monitor via unspecified vectors, possibly
  related to the EnableInvokerServletGlobally property in the servlet_jsp service. (CVE-2012-1291)

  Unspecified vulnerability in the MessagingSystem servlet in SAP NetWeaver 7.0 allows remote attackers to
  obtain sensitive information about the MessagingSystem Performance Data via unspecified vectors.
  (CVE-2012-1292)");

  script_tag(name:"impact", value:"A remote attacker may obtain sensitive information. An authenticated remote
  attacker may read arbitrary files.");

  script_tag(name:"affected", value:"Version 7.0");

  script_tag(name:"solution", value:"Check the references for solutions.");

  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/1585527");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/1583300");
  script_xref(name:"URL", value:"https://service.sap.com/sap/support/notes/1585527");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^7\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);