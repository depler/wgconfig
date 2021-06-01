using System;

namespace Wireguard.QRCode
{
    public class QrDataTooLongException : Exception
    {
        public QrDataTooLongException(string eccLevel, string encodingMode, int maxSizeByte) : base(
            $"The given payload exceeds the maximum size of the QR code standard. The maximum size allowed for the choosen paramters (ECC level={eccLevel}, EncodingMode={encodingMode}) is {maxSizeByte} byte."
        ){}

        public QrDataTooLongException(string eccLevel, string encodingMode, int version, int maxSizeByte) : base(
            $"The given payload exceeds the maximum size of the QR code standard. The maximum size allowed for the choosen paramters (ECC level={eccLevel}, EncodingMode={encodingMode}, FixedVersion={version}) is {maxSizeByte} byte."
        )
        { }
    }
}
