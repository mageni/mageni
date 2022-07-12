###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_evolution_script_cms_css_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Evolution Script CMS v5.3 - Cross Site Scripting Vulnerability
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

CPE = 'cpe:/a:evolution:script';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107219");
  script_version("$Revision: 11977 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-13 11:59:56 +0200 (Tue, 13 Jun 2017)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Evolution Script CMS v5.3 - Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Evolution Script CMS is vulnerable to Cross Site Scripting Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The cross site vulnerability is located in the 'status' parameter of the 'Ticket Support' module.");

  script_tag(name:"impact", value:"Remote attackers are able to inject own malicious script codes via GET method request.");

  script_tag(name:"affected", value:"Evolution Script CMS Version 5.3");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.

  A workaround is to parse or escape the status parameter content.
  Disallow the usage of special chars to prevent further script code injection attacks.
  Parse the ticket support content list and include an own exception-handling.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/14");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_evolution_script_detect.nasl");
  script_mandatory_keys("evolution_script/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE))
  exit(0);

if(!Ver = get_app_version(cpe:CPE, port: Port))
  exit(0);

if(version_is_equal(version: Ver, test_version:"5.3"))
{
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"None Available");
  security_message(data:report, port: Port);
  exit(0);
}

exit(99);
