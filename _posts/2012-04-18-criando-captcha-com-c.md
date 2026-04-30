---
layout: post
title: Criando CAPTCHA com C#
date: 2012-04-18 16:33:02.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/criando-captcha-com-c/"
---

CAPTCHA é um acrônimo da expressão "Completely Automated Public Turing test to tell Computers and Humans Apart" (teste de Turing público completamente automatizado para diferenciação entre computadores e humanos): um teste de desafio cognitivo, utilizado como ferramenta anti-spam evitando que aplicativos automatizados realize post em formulários sem uma interação humana.

Um tipo comum de CAPTCHA requer que o usuário identifique as letras de uma imagem distorcida, às vezes com a adição de uma sequência obscurecida das letras ou dos dígitos que apareça na tela.

Tendo como base essa descrição retirada do Wikipédia (http://pt.wikipedia.org/wiki/CAPTCHA), irei demonstrar como implementar um CAPTCHA utilizando C#.

Este código gera o CAPTCHA conforme os exemplos abaixo

[![Captcha Samples]({{ site.baseurl }}/assets/2012/04/captcha_samples.jpg)]({{ site.baseurl }}/assets/2012/04/captcha_samples.jpg)

<!--more-->

O Código que será utilizado foi retirado da internet em buscas pessoais, porém realizei diversos ajustes e melhorias objetivando torná-lo mais completo.

A Classe base de todo o processo foi nomeada como CaptchaImage e seu código segue abaixo

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;

public class CaptchaImage
{
    // Public properties (all read-only).
    public string Text
    {
        get { return this.text; }
    }

    public Bitmap Image
    {
        get { return this.image; }
    }

    public Byte[] PngImage
    {
        get
        {
            MemoryStream stream = new MemoryStream();
            this.image.Save(stream, ImageFormat.Png);

            Byte[] data = stream.ToArray();
            stream = null;

            return data;
        }
    }

    public String Base64PngImage
    {
        get
        {
            return Convert.ToBase64String(PngImage);
        }
    }

    public int Width
    {
        get { return this.width; }
    }

    public int Height
    {
        get { return this.height; }
    }

    // Internal properties.
    private string text;
    private int width;
    private int height;
    private string familyName;
    private Bitmap image;

    // For generating random numbers.
    private Random random = new Random();

    // ====================================================================
    // Initializes a new instance of the CaptchaImage class using the
    // specified width and height.
    // ====================================================================
    public CaptchaImage(Int32 length, Int32 width, Int32 height)
    {
        this.GenerateRandomCode(length);
        this.SetDimensions(width, height);
        this.GenerateImage();
    }

    // ====================================================================
    // Initializes a new instance of the CaptchaImage class using the
    // specified text, width and height.
    // ====================================================================
    public CaptchaImage(String s, Int32 width, Int32 height)
    {
        this.text = s;
        this.SetDimensions(width, height);
        this.GenerateImage();
    }

    // ====================================================================
    // Initializes a new instance of the CaptchaImage class using the
    // specified width, height and font family.
    // ====================================================================
    public CaptchaImage(Int32 length, Int32 width, Int32 height, String familyName)
    {
        this.GenerateRandomCode(length);
        this.SetDimensions(width, height);
        this.SetFamilyName(familyName);
        this.GenerateImage();
    }

    // ====================================================================
    // Initializes a new instance of the CaptchaImage class using the
    // specified text, width, height and font family.
    // ====================================================================
    public CaptchaImage(String s, Int32 width, Int32 height, String familyName)
    {
        this.text = s;
        this.SetDimensions(width, height);
        this.SetFamilyName(familyName);
        this.GenerateImage();
    }

    // ====================================================================
    // This member overrides Object.Finalize.
    // ====================================================================
    ~CaptchaImage()
    {
        Dispose(false);
    }

    // ====================================================================
    // Releases all resources used by this object.
    // ====================================================================
    public void Dispose()
    {
        GC.SuppressFinalize(this);
        this.Dispose(true);
    }

    // ====================================================================
    // Custom Dispose method to clean up unmanaged resources.
    // ====================================================================
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
            // Dispose of the bitmap.
            this.image.Dispose();
    }

    // ====================================================================
    // Generate Random Code of Captcha.
    // ====================================================================
    private void GenerateRandomCode(Int32 length)
    {
        List<String> codes = new List<String>();

        for (Int32 i = 65; i <= 90; i++)
        {
            codes.Add(Encoding.ASCII.GetString(new Byte[] { Byte.Parse(i.ToString("X"), System.Globalization.NumberStyles.HexNumber) }));
        }

        /*
        //Uncomment this for use Numeric text too
        for (Int32 i = 0; i <= 9; i++)
        {
            codes.Add(i.ToString());
        }*/

        for (Int32 i = 97; i <= 122; i++)
        {
            codes.Add(Encoding.ASCII.GetString(new Byte[] { Byte.Parse(i.ToString("X"), System.Globalization.NumberStyles.HexNumber) }));
        }

        Random rnd = new Random();
        string s = "";
        for (int i = 0; i < length; i++)
            s = String.Concat(s, codes[rnd.Next(0, codes.Count - 1)]);

        this.text = s;
    }

    // ====================================================================
    // Sets the image width and height.
    // ====================================================================
    private void SetDimensions(int width, int height)
    {
        // Check the width and height.
        if (width <= 0)
            throw new ArgumentOutOfRangeException("width", width, "Argument out of range, must be greater than zero.");
        if (height <= 0)
            throw new ArgumentOutOfRangeException("height", height, "Argument out of range, must be greater than zero.");
        this.width = width;
        this.height = height;
    }

    // ====================================================================
    // Sets the font used for the image text.
    // ====================================================================
    private void SetFamilyName(string familyName)
    {
        // If the named font is not installed, default to a system font.
        try
        {
            Font font = new Font(this.familyName, 12F);
            this.familyName = familyName;
            font.Dispose();
        }
        catch (Exception ex)
        {
            this.familyName = System.Drawing.FontFamily.GenericSerif.Name;
        }
    }

    // ====================================================================
    // Creates the bitmap image.
    // ====================================================================
    private void GenerateImage()
    {
        // Create a new 32-bit bitmap image.
        Bitmap bitmap = new Bitmap(this.width, this.height, PixelFormat.Format32bppArgb);

        Color backColor = Color.FromArgb((random.Next(100, 255)),
            (random.Next(100, 255)), (random.Next(100, 255)));

        Color foreColor = Color.FromArgb(random.Next(0, 100),
               random.Next(0, 100), random.Next(0, 100));

        // Create a graphics object for drawing.
        Graphics g = Graphics.FromImage(bitmap);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        Rectangle rect = new Rectangle(0, 0, this.width, this.height);

        HatchStyle[] aHatchStyles = new HatchStyle[]
            {
             HatchStyle.BackwardDiagonal, HatchStyle.Cross,
	            HatchStyle.DashedDownwardDiagonal, HatchStyle.DashedHorizontal,
             HatchStyle.DashedUpwardDiagonal, HatchStyle.DashedVertical,
	            HatchStyle.DiagonalBrick, HatchStyle.DiagonalCross,
             HatchStyle.Divot, HatchStyle.DottedDiamond, HatchStyle.DottedGrid,
	            HatchStyle.ForwardDiagonal, HatchStyle.Horizontal,
             HatchStyle.HorizontalBrick, HatchStyle.LargeCheckerBoard,
	            HatchStyle.LargeConfetti, HatchStyle.LargeGrid,
             HatchStyle.LightDownwardDiagonal, HatchStyle.LightHorizontal,
	            HatchStyle.LightUpwardDiagonal, HatchStyle.LightVertical,
             HatchStyle.Max, HatchStyle.Min, HatchStyle.NarrowHorizontal,
	            HatchStyle.NarrowVertical, HatchStyle.OutlinedDiamond,
             HatchStyle.Plaid, HatchStyle.Shingle, HatchStyle.SmallCheckerBoard,
	            HatchStyle.SmallConfetti, HatchStyle.SmallGrid,
             HatchStyle.SolidDiamond, HatchStyle.Sphere, HatchStyle.Trellis,
	            HatchStyle.Vertical, HatchStyle.Wave, HatchStyle.Weave,
             HatchStyle.WideDownwardDiagonal, HatchStyle.WideUpwardDiagonal, HatchStyle.ZigZag
            };

        // Fill in the background.
        HatchBrush hatchBrush = new HatchBrush(aHatchStyles[random.Next
            (aHatchStyles.Length - 1)], backColor, Color.White);
        g.FillRectangle(hatchBrush, rect);

        // Set up the text font.
        SizeF size;
        float fontSize = rect.Height * 2;
        Font font;

        // Adjust the font size until the text fits within the image.
        do
        {
            fontSize -= 0.3F;
            font = new Font(this.familyName, fontSize, FontStyle.Bold);
            size = g.MeasureString(this.text, font);
        } while ((size.Width > rect.Width) || (size.Height > rect.Height));

        fontSize = fontSize + (fontSize * 0.20F);
        font = new Font(this.familyName, fontSize, FontStyle.Bold);

        // Set up the text format.
        StringFormat format = new StringFormat();
        format.Alignment = StringAlignment.Center;
        format.LineAlignment = StringAlignment.Center;

        // Create a path using the text and warp it randomly.
        GraphicsPath path = new GraphicsPath();
        path.AddString(this.text, font.FontFamily, (int)font.Style, font.Size, rect, format);

        float v = 20F;
        PointF[] points =
			{
				new PointF(this.random.Next(rect.Width) / v, this.random.Next(rect.Height) / v),
				new PointF(rect.Width - this.random.Next(rect.Width) / v, this.random.Next(rect.Height) / v),
				new PointF(this.random.Next(rect.Width) / v, rect.Height - this.random.Next(rect.Height) / v),
				new PointF(rect.Width - this.random.Next(rect.Width) / v, rect.Height - this.random.Next(rect.Height) / v)
			};

        Matrix matrix = new Matrix();
        matrix.Translate(0F, 0F);
        path.Warp(points, rect, matrix, WarpMode.Perspective, 0F);

        // Draw the text.
        hatchBrush = new HatchBrush(hatchBrush.HatchStyle, foreColor, backColor);
        g.FillPath(hatchBrush, path);

        // Add some random noise.

        int m = Math.Max(rect.Width, rect.Height);
        for (int i = 0; i < (int)(rect.Width * rect.Height / 30F); i++)
        {
            int x = this.random.Next(rect.Width);
            int y = this.random.Next(rect.Height);
            int w = this.random.Next(m / 50);
            int h = this.random.Next(m / 50);
            g.FillEllipse(hatchBrush, x, y, w, h);
        }

        // Draw random lines
        Int32 linesCount = random.Next(3, 5);
        Pen lPen = new Pen(new SolidBrush(hatchBrush.ForegroundColor));
        for (Int32 l = 1; l <= linesCount; l++)
        {
            g.DrawLine(lPen,
                new Point(random.Next(0, this.width), random.Next(0, this.height)),
                new Point(random.Next(0, this.width), random.Next(0, this.height))
                );
        }

        // Clean up.
        font.Dispose();
        hatchBrush.Dispose();
        g.Dispose();

        // Set the image.
        this.image = bitmap;
    }
}
```

Para sua utilização há, pelo menos, duas metodologias possíveis, uma página que retornará uma imagem, ou uma tag <img> com o base64 da imagem.

Segue o código da página que retorna a imagem

```csharp
using System;
using System.Collections;
using System.Configuration;
using System.Data;
using System.Text;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.IO;
using System.Drawing;

public partial class EventImage : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        try
        {
            //Set Response code
            this.Response.StatusCode = 200;
            this.Response.Status = "200 OK";

            //Add last modified date
            this.Response.AddHeader("Last-Modified", DateTime.Now.ToString("r", System.Globalization.CultureInfo.CreateSpecificCulture("en-US")));

            //Change content type
            this.Response.ContentType = "image/png";

            //Create the captcha bitmap
            CaptchaImage cap = new CaptchaImage(6, 130, 40, "Verdana");

            //Get Byte array of image in PNG
            Byte[] imgData = cap.PngImage;

            //Set the byte array of the image in output stream
            this.Response.OutputStream.Write(imgData, 0, imgData.Length);

            //Set the session of the text for the captcha validation
            Session["captchaText"] = cap.Text;

        }
        catch (Exception ex)
        {
            //Set error response code
            this.Response.Status = "505 Internal error";
            this.Response.StatusCode = 505;
        }

    }
}
```

Segue o código para retorno do base64 da imagem

```csharp
//Create the captcha bitmap
CaptchaImage cap = new CaptchaImage(6, 130, 40, "Verdana");

Holder1.Controls.Add(new LiteralControl("<img border=\"0\" style=\"width: 200px; height: 50px; background: url('data:image/png;base64," + cap.Base64PngImage + "') no-repeat scroll 0px 0px transparent;\" src=\"/images/empty.gif\" title=\"Imagem de confirmação\">"));

//Set the session of the text for the captcha validation
Session["captchaText"] = cap.Text;
```

Note que em ambos as metodologias acima, foi gravado em uma sessão o texto do captcha, desta fora a validação pode ser realizada com esta sessão conforme exemplo abaixo

```csharp
String captchaText = Request.Form["captcha"];
String sCaptchaText = (String)Session["captchaText"];
if (sCaptchaText == null)
    sCaptchaText = "";

if (captchaText.ToLower() = sCaptchaText.ToLower())
{
    //OK
}
```
