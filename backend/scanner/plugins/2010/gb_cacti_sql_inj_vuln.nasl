##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_sql_inj_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Cacti 'export_item_id' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800772");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1431");
  script_bugtraq_id(39653);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Cacti 'export_item_id' Parameter SQL Injection Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0986");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=578909");
  script_xref(name:"URL", value:"http://www.exploit-db.com/sploits/Bonsai-SQL_Injection_in_Cacti.pdf");
  script_xref(name:"URL", value:"http://www.cacti.net/downloads/patches/0.8.7e/sql_injection_template_export.patch");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl");
  script_mandatory_keys("cacti/installed");

  script_tag(name:"insight", value:"Input passed to the 'templates_export.php' script via 'export_item_id' is
  not properly sanitized before being used in a SQL query.");

  script_tag(name:"summary", value:"This host is running Cacti and is prone to SQL injection vulnerability.");

  script_tag(name:"solution", value:"Apply the patch provided in the references.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access, modify or
  delete information in the underlying database.");

  script_tag(name:"affected", value:"Cacti version 0.8.7e and prior.");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version:"0.8.7e")) {
  security_message(port: port);
  exit(0);
}

exit(0);