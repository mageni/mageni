##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_justsystems_ichitaro_code_exec_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# JustSystems Ichitaro 'character attribute' Code Execution Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800794");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-2152");
  script_bugtraq_id(40472);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro 'character attribute' Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59037");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN17293765/index.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1283");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to corrupt memory to execute
  arbitrary code on the system.");
  script_tag(name:"affected", value:"JustSystems Ichitaro 2004 through 2009");
  script_tag(name:"insight", value:"The flaw is due to unspecified memory corruption error when processing
  'character attributes'.");
  script_tag(name:"solution", value:"Apply the patch, available");
  script_tag(name:"summary", value:"This host is installed JustSystems Ichitaro and is prone to code
  execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js10002.html");
  exit(0);
}


include("version_func.inc");

ichitaroVer = get_kb_item("Ichitaro/Ver");
if(ichitaroVer)
{
  if(version_in_range(version:ichitaroVer, test_version:"2004", test_version2:"2009")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
