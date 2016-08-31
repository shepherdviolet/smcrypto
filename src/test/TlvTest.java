package test;

import sviolet.smcrypto.tlv.IllegalPbocTlvFormatException;
import sviolet.smcrypto.tlv.PbocTlvElement;
import sviolet.smcrypto.tlv.PbocTlvParser;
import sviolet.smcrypto.util.Base64Utils;
import sviolet.smcrypto.util.ByteUtils;

import java.util.List;

/**
 * PBOC规范的TLV解析
 *
 * Created by S.Violet on 2016/8/31.
 */
public class TlvTest {

    private static final String certData = "MIICcDCCAhOgAwIBAgIFIBZSdVgwDAYIKoEcz1UBg3UFADBdMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRwwGgYDVQQDDBNDRkNBIFRFU1QgU00yIE9DQTExMB4XDTE2MDgxNTAzMTY1NFoXDTE4MDgxNTAzMTY1NFowfzELMAkGA1UEBhMCY24xFTATBgNVBAoMDENGQ0EgVEVTVCBDQTERMA8GA1UECwwITG9jYWwgUkExFTATBgNVBAsMDEluZGl2aWR1YWwtMzEvMC0GA1UEAwwmMDQxQDA0MjkwMDExOTg5MDUyMjMzMjFATGl1eXlAMDAwMDAwMDEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQ/x5BFOwpdSA8NWkFJjO3JXIbvm/9VjF2TQI1fm2IhMQ8tFadEdFEqhAREHcWEDfHInesiZYf4GADZhJGfHoNWo4GbMIGYMB8GA1UdIwQYMBaAFL6mfk09fI+gVebBLwkuLCBDs0J/MAwGA1UdEwEB/wQCMAAwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovLzIxMC43NC40Mi4zL09DQTExL1NNMi9jcmw4ODEuY3JsMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQU8ro8L0Z6Ih4oDXRyaq4BMJn7SKIwDAYIKoEcz1UBg3UFAANJADBGAiEAgBnN+ZCf80h7JK/ouSHWq+JV+TAiJNYupLr5yqHGIIgCIQDqx/nEliFVHp0QucNjkGPTZ1eqWnB4fwS3a7dE2lGkog==";

    public static void main(String[] args) throws IllegalPbocTlvFormatException {
        byte[] bytes = Base64Utils.decode(certData);
        //解析tlv数据
        PbocTlvElement element = PbocTlvParser.parse(bytes);
        System.out.println(ByteUtils.bytesToHex(element.getTag()));
        System.out.println(ByteUtils.bytesToHex(element.getLength()));
        System.out.println(ByteUtils.bytesToHex(element.getValue()));

        //如果是复合元素的话, 展开子元素
        if (element.isConstructed()) {
            //子元素
            List<PbocTlvElement> list = element.getSubElements();
        }

    }

}
