##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_prdts_mult_vuln_900202.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: CA kmxfw.sys Code Execution and DoS Vulnerabilities.
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900202");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-2926");
  script_bugtraq_id(30651);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("CA kmxfw.sys Code Execution and DoS Vulnerabilities");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=36560");
  script_xref(name:"URL", value:"http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=36559");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/495397/100/0/threaded");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020662.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020663.html");
  script_xref(name:"URL", value:"http://www.trapkit.de/advisories/TKADV2008-006.txt");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2008/Aug/0256.html");
  script_xref(name:"URL", value:"https://support.ca.com/irj/portal/anonymous/SolutionResults?aparNo=RO00535&actionID=4");
  script_xref(name:"URL", value:"ftp://ftp.ca.com/CAproducts/unicenter/CAHIPS/nt/0703/RO00535/RO00535.CAZ");

  script_tag(name:"summary", value:"This host is running CA Product(s), which is prone to Local Code
  Execution and Denial of Service Vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaw are due to insufficient verification/validation of IOCTL
  requests by the kmxfw.sys driver.");

  script_tag(name:"affected", value:"CA Internet Security Suite 2007 (v3.2) with CA Personal Firewall 2007 (v9.1) Engine version 1.2.260 and below

  CA Internet Security Suite 2008 (v4.0) with CA Personal Firewall 2008 (v10.0) Engine version 1.2.260 and below

  CA Personal Firewall 2007 (v9.1) with Engine version 1.2.260 and below

  CA Personal Firewall 2008 (v10.0) with Engine version 1.2.260 and below

  CA Host-Based Intrusion Prevention System r8");

  script_tag(name:"solution", value:"Ensure the latest engine is installed by using the built-in update
  mechanism and for Host-Based Intrusion Prevention System.");

  script_tag(name:"impact", value:"A remote/local user can cause denial of service conditions or
  execute arbitrary code by sending a specially crafted IOCTL requests.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 caEngVer = registry_get_sz(key:"SOFTWARE\CA\HIPSEngine", item:"Version");
 if(!caEngVer){
	exit(0);
 }

 if(egrep(pattern:"^(0\..*|1\.[01](\..*)?|1\.2(\.([01]?[0-9]?[0-9]|" +
		  "2[0-6][0-9]|27[0-5]))?)$",
                 string:caEngVer)){
       	security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
