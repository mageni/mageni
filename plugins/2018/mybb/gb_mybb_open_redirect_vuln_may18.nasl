###############################################################################
# OpenVAS Vulnerability Test
#
# MyBB Open Redirection Vulnerability-May18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
###############################################################################

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813403");
  script_version("2019-05-23T08:40:59+0000");
  script_cve_id("CVE-2018-10678");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-23 08:40:59 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-22 15:25:41 +0530 (Tue, 22 May 2018)");
  ## Affected only with with Microsoft Edge
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("MyBB Open Redirection Vulnerability-May18");

  script_tag(name:"summary", value:"The host is installed with MyBB and is
  prone to open redirection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as application fails to
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct phishing attacks. Other attacks are also possible.");

  script_tag(name:"affected", value:"MyBB version 1.8.15");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://gist.github.com/MayurUdiniya/7aaa50b878d82b6aab6ed0b3e2b080bc");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");
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

if(version == "1.8.15")
{
  report = report_fixed_ver(installed_version:version, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
