###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_soliddb_rpc_test_svc_dos_vuln.nasl 12014 2018-10-22 10:01:47Z mmartin $
#
# IBM solidDB RPC Test Commands Denial of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801937");
  script_version("$Revision: 12014 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 12:01:47 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-1208");
  script_bugtraq_id(47584);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("IBM solidDB RPC Test Commands Denial of Service Vulnerabilities");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025451");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67019");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1117");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-142/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_require_ports("Services/soliddb", 1315);
  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers to crash
  an affected process or consume CPU resources, creating a denial of service
  condition.");
  script_tag(name:"affected", value:"IBM solidDB 4.5.x before 4.5.182, 6.0.x before 6.0.1069, 6.1.x,
  6.3.x before 6.3 FP8, and 6.5.x before 6.5 FP4");
  script_tag(name:"insight", value:"The flaws are caused by a NULL pointer error in the solidDB component when
  processing the 'rpc_test_svc_readwrite' and 'rpc_test_svc_done commands'
  commands sent to port 2315/TCP.");
  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running IBM solidDB and is prone to multiple denial of service
  vulnerabilities.");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21496106");
  exit(0);
}


include("version_func.inc");

port = get_kb_item("Services/soliddb");
if(!port){
  port=1315;
}

if(!get_port_state(port)){
  exit(0);
}

if(!ver = get_kb_item(string("soliddb/",port,"/version"))){
  exit(0);
}

version = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9.]+)", string: ver);
if(version[1] != NULL){
  ver = version[1];
}

if(version_is_less(version:ver, test_version:"4.5.182"))
{
  security_message(port:port);
  exit(0);
}

if(ver =~ "^6\.0\.*")
{
  if(version_is_less(version:ver, test_version:"6.0.1069"))
  {
    security_message(port:port);
    exit(0);
  }
}

if(ver =~ "^6\.1\.*")
{
  security_message(port:port);
  exit(0);
}

if(ver =~ "^06\.3.*")
{
  if(version_is_less(version:ver, test_version:"06.30.0049"))
  {
    security_message(port:port);
    exit(0);
  }
}

if(ver =~ "^6\.5\.*")
{
  if(version_is_less(version:ver, test_version:"6.5.0.4")){
    security_message(port:port);
  }
}
