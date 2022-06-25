###############################################################################
# OpenVAS Vulnerability Test
#
# Redis LUA Multiple Vulnerabilities-Sep 2018 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:redis:redis";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.814022");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-19 12:54:11 +0530 (Wed, 19 Sep 2018)");
  script_name("Redis LUA Multiple Vulnerabilities-Sep 2018 (Linux)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is installed with Redis and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to Lua related
  issues in cmsgpack and other code paths when untrusted input is feed via
  the Lua API.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to corrupt the memory, violate the Redis process, and potentially
  taking total control of the Redis process.");

  script_tag(name:"affected", value:"Redis server versions before 3.2.12,
  4.0.x before 4.0.10 and 5.0 before 5.0rc2.");

  script_tag(name:"solution", value:"Upgrade Redis to version 3.2.12 or 4.0.10
  or 5.0rc2 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"http://antirez.com/news/119");
  script_xref(name:"URL", value:"http://download.redis.io");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");
  script_require_ports("Services/redis", 6379);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE )) exit(0);
version = infos['version'];
path = infos['location'];

if(version_is_less(version:version, test_version:"3.2.12")){
  fix = "3.2.12";
}
else if(version_in_range(version:version, test_version:"4.0", test_version2:"4.0.9")){
  fix = "4.0.10";
}
else if(version == "5.0rc1"){
  fix = "5.0rc2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
