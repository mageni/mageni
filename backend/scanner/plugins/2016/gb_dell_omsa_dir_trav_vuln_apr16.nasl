###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_omsa_dir_trav_vuln_apr16.nasl 11523 2018-09-21 13:37:35Z asteins $
#
# Dell OpenManage Server Administrator Directory Traversal Vulnerability - April16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dell:openmanage_server_administrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807564");
  script_version("$Revision: 11523 $");
  script_cve_id("CVE-2016-4004");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 15:37:35 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dell OpenManage Server Administrator Directory Traversal Vulnerability - April16");

  script_tag(name:"summary", value:"This host is installed with
  Dell OpenManage Server Administrator and is prone to directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of user supplied input via 'file' parameter to ViewFile.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated administrators to read arbitrary files on the affected system.");

  script_tag(name:"affected", value:"Dell OpenManage Server Administrator
  version 8.4 and prior.");

  script_tag(name:"solution", value:"Update to version 8.5");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://vuldb.com/?id.82281");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39486");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_omsa_remote_detect.nasl");
  script_mandatory_keys("Dell/OpenManage/Server/Administrator/Installed");
  script_require_ports("Services/www", 1311);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!omsPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!omsVer = get_app_version(cpe:CPE, port:omsPort)){
  exit(0);
}

if(version_is_less(version:omsVer, test_version:"8.5"))
{
  report = report_fixed_ver(installed_version:omsVer, fixed_version:"8.5");
  security_message(data:report, port:omsPort);
  exit(0);
}
