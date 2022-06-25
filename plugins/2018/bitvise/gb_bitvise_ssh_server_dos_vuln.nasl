################################################################################
# OpenVAS Vulnerability Test
#
# Bitvise SSH Server Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
################################################################################

CPE = "cpe:/a:bitvise:winsshd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813384");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Server Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is running Bitvise SSH Server
  Suite and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an invalid memory access
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause the SSH Server's main service to stop abruptly and also
  can cause the SSH Client to stop abruptly.");

  script_tag(name:"affected", value:"Bitvise SSH Server 6.xx before 6.51
  and 7.xx before 7.41.");

  script_tag(name:"solution", value:"Upgrade to version 6.51 or 7.41 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.bitvise.com/flowssh-version-history#security-notification-741");
  script_xref(name:"URL", value:"https://www.bitvise.com");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_bitvise_ssh_server_detect.nasl");
  script_mandatory_keys("BitviseSSH/Server/Version");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sshport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:sshport, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers =~ "^6\." && version_is_less(version:vers, test_version:"6.51")){
  fix = "6.51";
}
else if(vers =~ "^7\." && version_is_less(version:vers, test_version:"7.41")){
  fix = "7.41";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:sshport);
  exit(0);
}
exit(0);
