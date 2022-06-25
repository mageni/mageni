<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template name="generate-tags">
    <xsl:choose>
        <xsl:when test="contains(value, 'cpe:/o:3com')">
          <xsl:text>gsm_system_3com</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:alcatel')">
          <xsl:text>gsm_system_alcatel</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:apple:iphone')">
          <xsl:text>gsm_system_iphone</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:apple:mac_os')">
          <xsl:text>gsm_system_mac</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:apple')">
          <xsl:text>gsm_system_apple</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:bluecoat')">
          <xsl:text>gsm_system_bluecoat</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:brocade')">
          <xsl:text>gsm_system_brocade</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:canonical')">
          <xsl:text>gsm_system_ubuntu</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:centos')">
          <xsl:text>gsm_system_centos</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:cisco:ios')">
          <xsl:text>gsm_system_cisco_networking</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:cisco')">
          <xsl:text>gsm_system_cisco</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:compaq')">
          <xsl:text>gsm_system_compaq</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:conectiva')">
          <xsl:text>gsm_system_connectiva</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:corel')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:cray')">
          <xsl:text>gsm_system_cray</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:debian')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:engardelinux')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:extremenetworks')">
          <xsl:text>gsm_system_extremenetworks</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:f5')">
          <xsl:text>gsm_system_f5</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:fedoraproject')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:freebsd')">
          <xsl:text>gsm_system_freebsd</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:freenas')">
          <xsl:text>gsm_system_freenas</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:gentoo')">
          <xsl:text>gsm_system_gentoo</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:google:android')">
          <xsl:text>gsm_system_android</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:greenbone')">
          <xsl:text>gsm_system_gsm</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:hp:jetdirect')">
          <xsl:text>gsm_system_printserver</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:hp')">
          <xsl:text>gsm_system_hp</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:ibm')">
          <xsl:text>gsm_system_ibm</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:juniper')">
          <xsl:text>gsm_system_juniper</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:linux')">
          <xsl:text>gsm_system_linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:mandrakesoft')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:mandriva')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:ms-dos')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows-9x')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows-ce')">
          <xsl:text>gsm_system_wince</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_mobile')">
          <xsl:text>gsm_system_windows_mobile</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_2000')">
          <xsl:text>gsm_system_Windows_Server</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_vista')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows-nt')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_nt')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_server_2003')">
          <xsl:text>gsm_system_Windows_Server</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_2003')">
          <xsl:text>gsm_system_Windows_Server</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_7')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_server_2008')">
          <xsl:text>gsm_system_Windows_Server</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_2008')">
          <xsl:text>gsm_system_Windows_Server</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_server_2012')">
          <xsl:text>gsm_system_Windows_Server</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_8')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_8.1')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_10')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_xp')">
          <xsl:text>gsm_system_Windows_Client</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows_embedded')">
          <xsl:text>gsm_system_Windows_Embedded</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft:windows')">
          <xsl:text>gsm_system_windows_unknown</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:microsoft')">
          <xsl:text>gsm_system_microsoft</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:nec')">
          <xsl:text>gsm_system_nec</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:netbsd')">
          <xsl:text>gsm_system_netbsd</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:nokia')">
          <xsl:text>gsm_system_nokia</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:novell:netware')">
          <xsl:text>gsm_system_netware</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:novell')">
          <xsl:text>gsm_system_novell</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:openbsd')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:redhat')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:rim:blackberry')">
          <xsl:text>gsm_system_blackberry</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:sgi')">
          <xsl:text>gsm_system_sgi</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:siemens')">
          <xsl:text>gsm_system_siemens</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:slackware')">
          <xsl:text>gsm_system_slackware</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:starnet')">
          <xsl:text>gsm_system_starnet</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:sun')">
          <xsl:text>gsm_system_sun</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:suse')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:trustix')">
          <xsl:text>gsm_system_Linux</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:univention')">
          <xsl:text>gsm_system_univention</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:vmware')">
          <xsl:text>gsm_system_vmware</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:windriver')">
          <xsl:text>gsm_system_windriver</xsl:text>
        </xsl:when>
        <xsl:when test="contains(value, 'cpe:/o:yamaha')">
          <xsl:text>gsm_system_yamaha</xsl:text>
        </xsl:when>
      <xsl:otherwise>
        <xsl:text>gsm_system_unkown</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>
