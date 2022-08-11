###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netvault_backup_dos_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Dell Netvault Denial Of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dell:netvault_backup";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806003");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5696");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-04 16:15:42 +0530 (Tue, 04 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dell Netvault Denial Of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Dell Netvault
  Backup and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  validation of user-supplied input which cause the 'nvpmgr.exe' process on an
  affected system to crash.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service vulnerability (crash).");

  script_tag(name:"affected", value:"Dell Netvault Backup versions 10.0.1.24
  and probably prior");

  script_tag(name:"solution", value:"Upgrade to Dell Netvault Backup version
  10.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.76847");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jul/142");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132928/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_netvault_backup_detect.nasl");
  script_mandatory_keys("dell/netvaultbackup/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://software.dell.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!netPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!netVer = get_app_version(cpe:CPE, port:netPort)){
  exit(0);
}

if(version_is_less_equal(version:netVer, test_version:"10.0.1.24"))
{
  report = 'Installed Version: ' +netVer+ '\n' +
           'Fixed Version:     '+"10.0.5"+ '\n';
  security_message(data:report, port:netPort);
  exit(0);
}
