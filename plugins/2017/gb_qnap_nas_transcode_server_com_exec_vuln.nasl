###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_nas_transcode_server_com_exec_vuln.nasl 7791 2017-11-16 13:18:39Z jschulte $
#
# QNAP NAS 'Transcode Server' Command Execution Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/h:qnap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811727");
  script_version("$Revision: 7791 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-16 14:18:39 +0100 (Thu, 16 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-09-01 10:43:16 +0530 (Fri, 01 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("QNAP NAS 'Transcode Server' Command Execution Vulnerability");

  script_tag(name:"summary", value:"This host is running QNAP NAS device and
  is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect nvt and check whether it is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to error in 'rmfile' command
  in Transcode Server which does not filter certain special characters and allow
  them to pass in the command.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary commands on the remote affected device.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"QNAP TS-431 with firmware version 4.3.3.0262
  (20170727) and QNAP_TS-131. Many other QNAP models may also be affected.");

  script_tag(name: "solution" , value:"No solution or patch exists as of
  16th November, 2017. Information regarding this issue will be updated once solution
  details are available. For updates refer to,
  https://www.qnap.com");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://www.exploitee.rs/index.php/QNAP_TS-131");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/42587");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");
  script_require_ports("Services/www", 80, 8080);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

# Variable Initialization
version = 0;
qtsPort = 0;

##Get Port
if(!qtsPort = get_app_port_from_cpe_prefix(cpe:CPE)){
  exit(0);
}

##Get model
if (!model = get_kb_item("qnap/dismodel")){
  exit(0);
}

##Check for model affected
if(model != "((TS-131)|(TS-431))"){
  exit(0);
}

##Get version
if (!version = get_kb_item("qnap/version")){
  exit(0);
}

##Get Build
if (!build = get_kb_item("qnap/build")){
  exit(0);
}

##Combine build and version
checkvers = version + '.' + build;

if((model == "TS-431" && checkvers == "4.3.3.0262.20170727") ||
   (model == "TS-131"))
{
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "None Available");
  security_message(port:qtsPort, data: report);
  exit(0);
}
exit(0);
