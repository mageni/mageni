###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_mult_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# dotCMS Multiple Vulnerabilities
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

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106116");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-05 08:55:18 +0700 (Tue, 05 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-2355", "CVE-2016-3688", "CVE-2016-3971", "CVE-2016-3972", "CVE-2016-4040",
                "CVE-2016-4803");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("dotCMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_detect.nasl");
  script_mandatory_keys("dotCMS/installed");

  script_tag(name:"summary", value:"dotCMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"dotCMS is prone to multiple vulnerabilities:

A SQL injection attack is possible via the Content REST api if the api is set to allow for anonymous
content saving (which is the shipped default). (CVE-2016-2355)

A SQL injection vulnerability allows remote administrators to execute arbitrary SQL commands via the
c0-e3 parameter to dwr/call/plaincall/UserAjax.getUsersList.dwr. (CVE-2016-3688)

A cross-site scripting (XSS) vulnerability in lucene_search.jsp allows remote authenticated administrators
to inject arbitrary web script or HTML via the query parameter to c/portal/layout. (CVE-2016-3971)

A directory traversal vulnerability in the dotTailLogServlet allows remote authenticated administrators
to read arbitrary files via a .. (dot dot) in the fileName parameter. (CVE-2016-3972)

A SQL injection vulnerability in the Workflow Screen allows remote administrators to execute arbitrary
SQL commands via the orderby parameter. (CVE-2016-4040)

A CRLF injection vulnerability in the send email functionality allows remote attackers to inject arbitrary
email headers via CRLF sequences in the subject. (CVE-2016-4803)");

  script_tag(name:"impact", value:"An attacker may access sensitive information in the dotcms database.");

  script_tag(name:"affected", value:"Version 3.3.1 and previous versions.");

  script_tag(name:"solution", value:"Update to 3.3.2 or later versions.");

  script_xref(name:"URL", value:"http://dotcms.com/security/SI-32");
  script_xref(name:"URL", value:"http://dotcms.com/security/SI-33");
  script_xref(name:"URL", value:"http://dotcms.com/security/SI-34");
  script_xref(name:"URL", value:"http://dotcms.com/security/SI-35");
  script_xref(name:"URL", value:"http://dotcms.com/security/SI-36");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
