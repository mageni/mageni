###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_disk_savvy_bof_vul_feb17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# DiskSavvy Enterprise GET Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:disksavvy:disksavvy_enterprise_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107130");
  script_version("$Revision: 11863 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-02 12:21:46 +0100 (Thu, 02 Feb 2017)");
  script_name("DiskSavvy Enterprise GET Buffer Overflow (Windows)");

  script_tag(name:"summary", value:"This host is installed with DiskSavvy Enterprise and is prone to a GET buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Vulnerability is due to an improper checking of the GET http request sent to the web server which might be exploited to cause a buffer overflow.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"DiskSavvy Enterprise 9.1.14 and 9.3.14");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41146/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_disk_savvy_enterprise_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("DiskSavvy/Enterprise/Server/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!Port = get_app_port(cpe:CPE)){
    exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if (version_is_equal(version:Ver, test_version:"9.1.14") || version_is_equal(version:Ver, test_version:"9.3.14"))
{
   report = report_fixed_ver(installed_version:Ver, fixed_version:"None Available");
   security_message(data:report, port: Port);
   exit(0);
}

exit(99);
