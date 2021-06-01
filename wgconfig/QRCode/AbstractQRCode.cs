namespace Wireguard.QRCode
{
    public abstract class AbstractQRCode
    {
        protected QRCodeData QrCodeData { get; set; }

        protected AbstractQRCode()
        {
        }

        protected AbstractQRCode(QRCodeData data)
        {
            QrCodeData = data;
        }

        virtual public void SetQRCodeData(QRCodeData data)
        {
            QrCodeData = data;
        }

        public void Dispose()
        {
            QrCodeData?.Dispose();
            QrCodeData = null;
        }
    }
}