###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_mod_jk_info_disc_vuln.nasl 12927 2019-01-03 05:43:34Z ckuersteiner $
#
# Apache Tomcat mod_jk Information Disclosure Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:mod_jk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800277");
  script_version("$Revision: 12927 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 06:43:34 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-5519");
  script_bugtraq_id(34412);

  script_name("Apache Tomcat mod_jk Information Disclosure Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_mod_jk_detect.nasl");
  script_mandatory_keys("apache_modjk/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"This issue can be exploited to disclose response data associated with the
  request of a different user via specially crafted HTTP requests and to gain
  sensitive information about the remote host.");

  script_tag(name:"affected", value:"Apache Tomcat mod_jk version 1.2.0 to 1.2.26");

  script_tag(name:"insight", value:"This flaw is due to

  - an error when handling empty POST requests with a non-zero 'Content-Length' header.

  - an error while handling multiple noncompliant AJP protocol related requests.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to mod_jk 1.2.27 or later.");

  script_tag(name:"summary", value:"This host is running Apache Tomcat with mod_jk Module and is prone to
  Information Disclosure vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34621");
  script_xref(name:"URL", value:"http://marc.info/?l=tomcat-dev&m=123913700700879");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022001.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: cpe))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "1.2.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.27");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
