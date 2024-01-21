let sliderContent = [
  {
    name: "MACKBOOK",
    price: 1500,
    details: [
      "2,9 GHz Dual‑Core Intel Core i5",
      "256 GB SSD auf PCIe Basis (On‑Board)",
      "8 GB 2133 MHz LPDDR3 Arbeitsspeicher",
    ],
  },
  {
    name: "HEADPHONES",
    price: 200,
    details: [
      "Balanced High, Mid and Low tones",
      "Active Noise Cancellation",
      "Bluetooth Wireless",
    ],
  },
  {
    name: "WATCH",
    price: 399,
    details: [
      "Dual‑Core Processor, Integrated GPS",
      "WIFI (802.11b/g/n 2,4 GHz), Bluetooth 4.0",
      "OLED Retina Display",
      "312 x 390 Pixel (42 mm)",
    ],
  },
];

const popoutAnimation = [
  { transform: 'scale(0) translateY(-20px)' },
  { transform: 'scale(1) translateY(0)' }
]

const popoutAnimationDetails = {
  duration: 800,
  easing: 'ease-in-out',
  iterations: 1, 
  fill: 'forwards'
}


let sliderAt = 0;

const sliderHeader = document.querySelector(".slider-content h1");
const price = document.querySelector(".price");
const leftarrow = document.querySelector(".left-slide-arrow");
const rightarrow = document.querySelector(".right-slide-arrow");
const sliderImages = document.querySelectorAll(".slider-images");

const watches = document.querySelectorAll(".watches");

const laptop = document.querySelector(".laptop");
const headphone = document.querySelector(".headphones");

window.addEventListener('load', ()=>{
  sliderHeader.animate(popoutAnimation, popoutAnimationDetails)
  laptop.animate(popoutAnimation, popoutAnimationDetails)
})

setInterval(()=>{
  if(sliderAt == 3){
    sliderAt = 0
    updateSlide()
  } else {
    sliderAt++
    updateSlide()
  }
}, [7000])


leftarrow.addEventListener("click", () => {
  if (sliderAt == 0) {
    sliderAt = 2;
  } else {
    sliderAt--;
  }
  updateSlide();
});

rightarrow.addEventListener("click", () => {
  if (sliderAt == 2) {
    sliderAt = 0;
  } else {
    sliderAt++;
  }
  updateSlide();
});

function updateSlide() {
  if (sliderAt == 0) {
    laptop.style.display = "block";
    headphone.style.display = "none";
    for (let watch of watches) {
      watch.style.display = "none";
    }
    sliderHeader.animate(popoutAnimation, popoutAnimationDetails)
    laptop.animate(
      {
        opacity: [0, 1],
        transform: ["scale(0)", "scale(1)"],
      },
      {
        duration: 800,
      }
    );
  }
  if (sliderAt == 1) {
    laptop.style.display = "none";
    headphone.style.display = "block";
    for (let watch of watches) {
      watch.style.display = "none";
    }

    sliderHeader.animate(popoutAnimation, popoutAnimationDetails)
    headphone.animate(
      {
        opacity: [0, 1],
        transform: ["scale(0)", "scale(1)"],
      },
      {
        duration: 800,
      }
    );
  }

  if (sliderAt == 2) {
    laptop.style.display = "none";
    headphone.style.display = "none";

    document.querySelector('.price-circle').style.transform = 'translate(225px, -100px)'

    sliderHeader.animate(popoutAnimation, popoutAnimationDetails)
    for (let watch of watches) {
      watch.style.display = "block";
      if(watch.classList.contains("watch02")){
        watch.animate(
          {
            opacity: [0, 1],
            transform: [
              "scale(0)", "scale(1)"
            ],
          },
          {
            duration: 800,
          }
        );
      } else if (watch.classList.contains("watch01")){
        watch.animate(
          {
            opacity: [0, 1],
            transform: [
              "scale(0) translateX(0px) rotate(0deg)", "scale(1) translateX(-150px) rotate(-20deg)"
            ],
          },
          {
            duration: 800,
          }
        );
      } else{
        watch.animate(
          {
            opacity: [0, 1],
            transform: [
              "scale(0) translateX(0px) rotate(0deg)", "scale(1) translateX(150px) rotate(20deg)"
            ],
          },
          {
            duration: 800,
          }
        );
      }
    }
  }

  sliderHeader.innerText = sliderContent[sliderAt].name;
  price.innerText = "RM"+sliderContent[sliderAt].price ;

  let sliderdetail = "";
  sliderContent[sliderAt].details.map((detail) => {
    sliderdetail += `
        <div class="slider-content-details">
            <div>
                <span class="slider-content-check"><i class="fa-solid fa-check"></i></span>
                <span>${detail}</span>
            </div>
        </div>`;
  });
  sliderdetail += "<button>ADD TO CART</button>";
  document.querySelector(".slider-content-footer").innerHTML = sliderdetail;
}
