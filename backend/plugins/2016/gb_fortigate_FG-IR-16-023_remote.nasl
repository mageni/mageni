###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortigate_FG-IR-16-023_remote.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# FortiOS: Cookie Parser Buffer Overflow Vulnerability (remote check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105886");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-6909");
  script_name("FortiOS: Cookie Parser Buffer Overflow Vulnerability (remote check)");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-16-023");

  script_tag(name:"impact", value:"This vulnerability, when exploited by a crafted HTTP request, can result in execution control being taken over.");

  script_tag(name:"vuldetect", value:"Check the Etag");
  script_tag(name:"solution", value:"Upgrade to release 5.x.
Upgrade to release 4.3.9 or above for models not compatible with FortiOS 5.x.");

  script_tag(name:"summary", value:"FortiGate firmware (FOS) released before Aug 2012 has a cookie parser buffer overflow vulnerability.");

  script_tag(name:"affected", value:"FortiGate (FOS):

4.3.8 and below

4.2.12 and below

4.1.10 and below");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-06 11:28:49 +0200 (Tue, 06 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ETag/banner");

  exit(0);
}


include("http_func.inc");

include("misc_func.inc");

port = get_http_port( default:443 );

banner = get_http_banner( port:port );
if( ! banner || "ETag" >!< banner ) exit( 0 );

etag = eregmatch( pattern:'ETag: "([^"]+)"', string:banner );
if( isnull(etag[1] ) ) exit( 0 );

etag = split( etag[1], sep:"-", keep:FALSE );
if( ( max_index( etag ) < 3 ) ) exit( 0 );

et = etag[2];
if( strlen( et ) != 8 ) exit( 0 );

etags = make_list( "44443fd4","44c526c5","45a3ea60","45baacf4","45f0af67","47e0669f","468abbad","46c6166d",
                   "46df457c","4602cf97","463b99a6","468cad93","46d9607c","47b355de","489129e7","443ede0d",
                   "44c52c4f","452184d7","45a3f01e","45bab263","45f0b580","4602cfe5","463b9965","468cbb86",
                   "46d9672a","471d2e73","47b355da","47e06d95","48912069","468ac1d0","46a7ad09","46c61f79",
                   "46df4da9","4717beff","474b9480","47bcda2f","48b30fac","490bb64e","47a3f4ee","47df4682",
                   "482b72f5","488fa68e","49064b4d","49ae1d20","487e7a57","48d43154","49273663","49ade40f",
                   "49c45c70","49dd033a","4a4a955b","4ace863a","4b3185d6","4b7c8347","4cc1d9e0","4a384886",
                   "4b0f40be","4a8de859","4ade3518","4b318abd","4b58d924","4ba3e7e6","4c22a3f3","4c2a8446",
                   "4c88306f","4ca38e08","4d435410","4dfaabba","ff80c272","ff80c279","4c74581f","4d083087",
                   "4d6d53b0","4d93bdf9","4dae0eb8","4dd6af49","4e2496ed","4d84169e","4e090fe3","44443ed6",
                   "44c52afa","4522b784","45500063","45a3f02e","45bab272","45f0ba4d","460d7a1f","463aa4d2",
                   "46806d0b","46cb9bfc","47e06dbe","48913626","45948af9","45a6f4c1","45ba73c7","45f1c561",
                   "460d88a0","468ac251","468321e2","46c61fcf","46df4e86","4717c14d","474b9d17","47bcdc5c",
                   "48b312ee","490bb6a0","47a3f5a7","47df4721","482b7090","488faa33","49064b4b","49ae254b",
                   "49ffa204","487e7ecc","48d43248","492737d4","49adeaae","49c45cd3","49dd05b9","4a4aec23",
                   "4acfd94e","4b328455","4b7c709c","4cc85189","499f3750","49db8b32","4a37e55a","4b16d0ce",
                   "4a8de79b","4ade32fe","4b318bb4","4b58d9e4","4ba3e887","4c22a8f5","4c2a8e5f","4c882f51",
                   "4ca39510","4d4359e1","4dfab1c1","ff2a0272","ff2a0279","4c746630","4d083771","4d6d57f7",
                   "4d93c93e","4dae1c33","4dd6be44","4e24a35c","4d8404a9","4e08fc94","443ed96e","44c52523",
                   "4522a9b7","454ff829","45a3eee4","45baafe1","45f0b528","460d78e2","463a9d82","468066d7",
                   "46cb9803","47e06db5","48913369","45948486","45a6ed51","45ba6c80","45f1bee7","460d84ba",
                   "468ac195","46831ae7","46c61d81","46df4be9","4717b955","474b9368","47bce039","48b309de",
                   "490bb553","47a3eb7d","47df39f8","482b665b","488f9d9e","49063f0f","49ae0f61","49ff87ee",
                   "487e6e64","48d42a0e","49272ac0","49adcf83","49c4428a","49dcea97","4a4ac8a2","4acfb690",
                   "4b329ac9","4b7c0774","4cc85360","499f36b3","49db8a40","4a37e407","4b16ce6b","4a8de5fb",
                   "4ade33db","4b318b1d","4b58d915","4ba3e740","4c22a3f3","4c2a87f3","4c88270e","4ca3911b",
                   "4d4348f3","4dfaabc1","ff3a0272","ff3a0279","4c745c40","4d082d04","4d6d537d","4d93ba56",
                   "4dae0ccf","4dd6af6d","4e2496d3","4d83fb16","4e08f34e","45218416","454ffff6","45a3f2a2",
                   "45bab65e","45f0bb96","482b785e","490651ca","487e7fcd","48d438a9","49273e0c","49adecc7",
                   "49c471d3","49dd07b8","4a4aeee3","499f381f","49db8b9d","4a37e5ed","4b16d150","4a8de874",
                   "4ade3634","4b318c6f","4b58da4a","4ba3ea3a","4c22abac","4c2a8b64","4c88304b","4ca394e0",
                   "4d435b90","4dfab44e","ff4a0272","ff4a0279","4c746382","4d083d66","4d6d6086","4d93cef4",
                   "4dae1d25","4dd6bce0","4e24a478","4fd0169d","4d840fc3","4e08fe48","48d434a1","499f37d5",
                   "49db8c53","4a37e619","4b16d14f","4a8de872","4ade35c8","4b318c8f","4b58d602","4ba3ea39",
                   "ff5a0272","48ebf4e5","49a726b1","49c2f6eb","49d50ba6","4a4972e5","4acf7bf4","4b317cd0",
                   "4b7c83e9","4cc07c21","499f3876","49db8a8c","4a37e799","4b16ce32","4a8de5dd","4ade354e",
                   "4b31890b","4b58d766","4ba3e517","4c22a1af","4c2a8997","4c882a6e","4ca38e77","4d434d71",
                   "4dfaaa8e","ff6b0272","ff6b0279","4c745805","4d0830cf","4d6d4f28","4d93c137","4dae0619",
                   "4dd6af65","4e2494a1","4d8402ca","4e090c3c","443ed9bc","44c524a6","45217d85","45a3e9c5",
                   "45baac66","45f0aeca","460d732c","463a98c5","46806671","46cb95bb","47e0676b","48912cc2",
                   "459484d8","45a6eda3","45ba6ce1","45f1bf6b","460d8176","468abbd8","4683142d","46c618cd",
                   "46df475e","4717baf9","474b9010","47bcd6f0","48b30c5e","490bb4a5","47a3e919","47df3b36",
                   "482b67a1","488f9d2b","49063c22","49ae068e","49ff8382","487e6b1d","48d4212c","4927278f",
                   "49adc356","49c43b4e","49dcde89","4a4ac12f","4acfae3e","4b32925e","4b7bff1f","4cc8529a",
                   "499f3690","49db8a5a","4a37e3fe","4b16ce96","4a8de623","4ade32d7","4b318927","4b58d762",
                   "4ba3e573","4c229fca","4c2a82c9","4c882661","4ca391ed","4d434fb7","4dfaabbb","ff800272",
                   "ff800279","4c74569a","4d082af0","4d6d5188","4d93ba54","4dae0da0","4dd6af1e","4e2496ea",
                   "4d84181e","4e090fbe","45a6edd5","82ffffff","83ffffff","45217ec9","49064d61","46d96863",
                   "49d11af3","46cb9c1e","4acff334" );

if( in_array( search:et, array:etags ) )
{
  report = 'The Etag "' + et + '" of the remote Forti device was found in the "EGBL.config" and therefore the device is affected by a security bypass.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

