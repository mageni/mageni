###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qts_media_library_com_inj_vuln.nasl 14300 2019-03-19 07:52:26Z mmartin $
#
# QNAP QTS 'Media Library' Command injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811772");
  script_version("$Revision: 14300 $");
  script_cve_id("CVE-2017-13067");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 08:52:26 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-09-19 09:42:48 +0530 (Tue, 19 Sep 2017)");
  script_name("QNAP QTS 'Media Library' Command injection Vulnerability");

  script_tag(name:"summary", value:"This host is running QNAP QTS and is prone
  to command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some error in the
  'QTS Media Library' using a transcoding service on port 9251.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands on the target system.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.x prior to 4.2.6 build
  20170905 and 4.3.x prior to 4.3.3.0299 build 20170901.");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS 4.2.6 build 20170905 or
  4.3.3.0299 build 20170901.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.qnap.com/en-uk/support/con_show.php?cid=129");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts", "qnap/version", "qnap/build");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("version_func.inc");

if (!qnapPort = get_kb_item("qnap/port")){
  exit(0);
}

if (!version = get_kb_item("qnap/version")){
  exit(0);
}

if(!build = get_kb_item("qnap/build")){
  exit(0);
}

qnapVer = version + '.' + build;

if(qnapVer =~ "^(4\.2)" && version_is_less(version:qnapVer, test_version: "4.2.6.20170905")){
  fix = "4.2.6 build 20170905";
}

else if(qnapVer =~ "^(4\.3)" && version_is_less(version:qnapVer, test_version: "4.3.3.0299.20170901")){
  fix = "4.3.3.0299 build 20170901";
}

if(fix){
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:fix);
  security_message( port:qnapPort, data:report );
  exit(0);
}

exit(99);
