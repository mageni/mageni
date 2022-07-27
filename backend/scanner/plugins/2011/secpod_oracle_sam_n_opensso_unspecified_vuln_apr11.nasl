###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_sam_n_opensso_unspecified_vuln_apr11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle Java Access Manager and OpenSSO Unspecified Vulnerability - April11
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902422");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-0844", "CVE-2011-0847");
  script_bugtraq_id(47490, 47481);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Oracle Java Access Manager and OpenSSO Unspecified Vulnerability - April11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_opensso_detect.nasl", "secpod_sjs_access_manager_detect.nasl");
  script_mandatory_keys("JavaSysAccessManger_or_OracleOpenSSO/detected");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to affect confidentiality
  and integrity via unknown vectors.");

  script_tag(name:"affected", value:"Sun OpenSSO Enterprise version 8.0,

  Java System Access Manager version 7.1");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors in the application, which allow
  remote attackers to affect confidentiality and integrity via unknown vectors.");

  script_tag(name:"summary", value:"The host is running Access Manager or OpenSSO and is prone to
  unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the security updates.
  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken...

  exit(0);
}

include("http_func.inc");

am_port = get_http_port(default:8080);

amVer = get_kb_item("www/" + am_port + "/Sun/JavaSysAccessManger");
amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);

if(amVer[1] =~ "7.1")
{
  security_message(am_port);
  exit(0);
}

ssoVer = get_kb_item("www/" + am_port + "/Sun/OpenSSO");
ssoVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ssoVer);

if(ssoVer[1] =~ "8.0"){
  security_message(am_port);
}
